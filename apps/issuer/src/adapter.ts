import { errors, type Adapter, type AdapterPayload } from "oidc-provider";
import { decryptOidcClientSecret, decryptOidcPayload, encryptOidcPayload, hashOidcIdentifier } from "@virki/auth/oidc-secrets";
import { prisma, type PrismaClient } from "@virki/database";

const grantBoundModels = new Set([
  "AccessToken",
  "AuthorizationCode",
  "RefreshToken",
  "DeviceCode",
  "BackchannelAuthenticationRequest",
  "PreAuthorizedCode"
]);
const projectAuthorizationModels = new Set([...grantBoundModels, "Grant"]);

export class PrismaOidcAdapter implements Adapter {
  constructor(private readonly model: string, private readonly database: Pick<PrismaClient, "oidcArtifact" | "projectConnection" | "$transaction"> = prisma) {}

  async upsert(id: string, payload: AdapterPayload, expiresIn: number): Promise<void> {
    if (this.model === "Client") throw new Error("Client metadata is managed through project connections.");
    const data = {
      payloadCiphertext: encryptOidcPayload(JSON.stringify(payload)),
      grantHash: grantBoundModels.has(this.model) && payload.grantId ? hashOidcIdentifier(payload.grantId) : null,
      uidHash: payload.uid ? hashOidcIdentifier(payload.uid) : null,
      userCodeHash: payload.userCode ? hashOidcIdentifier(payload.userCode) : null,
      clientIdHash: payload.clientId ? hashOidcIdentifier(payload.clientId) : null,
      accountIdHash: payload.accountId ? hashOidcIdentifier(payload.accountId) : null,
      expiresAt: Number.isFinite(expiresIn) && expiresIn > 0 ? new Date(Date.now() + expiresIn * 1000) : null,
      consumedAt: payload.consumed ? new Date(Number(payload.consumed) * 1000) : null
    };
    const artifact = {
      where: { model_idHash: { model: this.model, idHash: hashOidcIdentifier(id) } },
      update: data,
      create: { model: this.model, idHash: hashOidcIdentifier(id), ...data }
    };
    if (!projectAuthorizationModels.has(this.model)) {
      await this.database.oidcArtifact.upsert(artifact);
      return;
    }

    const { accountId, clientId } = getProjectAuthorizationContext(payload, grantBoundModels.has(this.model));
    await this.database.$transaction(async (transaction) => {
      const activeGrant = await transaction.$queryRaw<Array<{ id: string; redirectUris: unknown }>>`
        SELECT grant_record."id", connection_record."redirectUris" AS "redirectUris"
        FROM "UserProjectGrant" AS grant_record
        INNER JOIN "User" AS account_record ON account_record."id" = grant_record."userId"
        INNER JOIN "ProjectConnection" AS connection_record ON connection_record."id" = grant_record."connectionId"
        WHERE grant_record."userId" = ${accountId}
          AND connection_record."clientId" = ${clientId}
          AND grant_record."revokedAt" IS NULL
          AND account_record."role" = 'USER'
          AND account_record."isActive" = TRUE
          AND account_record."accountStatus" = 'ACTIVE'
          AND connection_record."enabled" = TRUE
        FOR UPDATE OF grant_record, account_record, connection_record
      `;
      if (activeGrant.length !== 1) throw new errors.InvalidGrant("OIDC authorization is no longer active.");
      if (this.model === "AuthorizationCode" && (typeof payload.redirectUri !== "string" || !stringArray(activeGrant[0].redirectUris).includes(payload.redirectUri))) {
        throw new Error("OIDC redirect URI is no longer registered.");
      }
      if (grantBoundModels.has(this.model)) {
        // An account-level purge deletes the provider Grant while holding the User row lock taken above, so this check serializes with it.
        const providerGrant = await transaction.oidcArtifact.findUnique({
          where: { model_idHash: { model: "Grant", idHash: hashOidcIdentifier(payload.grantId as string) } },
          select: { expiresAt: true }
        });
        if (!providerGrant || (providerGrant.expiresAt && providerGrant.expiresAt <= new Date())) throw new errors.InvalidGrant("OIDC provider grant is no longer active.");
      }
      await transaction.oidcArtifact.upsert(artifact);
    });
  }

  async find(id: string): Promise<AdapterPayload | undefined> {
    if (this.model === "Client") return this.findClient(id);
    return this.readArtifact(await this.database.oidcArtifact.findUnique({ where: { model_idHash: { model: this.model, idHash: hashOidcIdentifier(id) } } }));
  }

  async findByUid(uid: string): Promise<AdapterPayload | undefined> {
    return this.readArtifact(await this.database.oidcArtifact.findFirst({ where: { model: this.model, uidHash: hashOidcIdentifier(uid) } }));
  }

  async findByUserCode(userCode: string): Promise<AdapterPayload | undefined> {
    return this.readArtifact(await this.database.oidcArtifact.findFirst({ where: { model: this.model, userCodeHash: hashOidcIdentifier(userCode) } }));
  }

  async consume(id: string): Promise<void> {
    const where = { model_idHash: { model: this.model, idHash: hashOidcIdentifier(id) } };
    const record = await this.database.oidcArtifact.findUnique({ where, select: { payloadCiphertext: true } });
    // A code found by the provider but gone now was revoked by a concurrent replay of the same grant.
    if (!record) throw new errors.InvalidGrant("authorization code is no longer valid");
    const payload = parsePayload(decryptOidcPayload(record.payloadCiphertext));
    if (payload.consumed) await this.rejectReplay(payload);
    payload.consumed = Math.floor(Date.now() / 1000);
    const consumed = await this.database.oidcArtifact.updateMany({
      where: { model: this.model, idHash: hashOidcIdentifier(id), consumedAt: null },
      data: { payloadCiphertext: encryptOidcPayload(JSON.stringify(payload)), consumedAt: new Date() }
    });
    if (consumed.count !== 1) await this.rejectReplay(payload);
  }

  // Losing the one-time consume race is a replay: answer invalid_grant (not a 500) and revoke the grant, as the provider does for a code it sees already consumed.
  private async rejectReplay(payload: AdapterPayload): Promise<never> {
    if (typeof payload.grantId === "string" && payload.grantId) await this.revokeByGrantId(payload.grantId);
    throw new errors.InvalidGrant("authorization code already consumed");
  }

  async destroy(id: string): Promise<void> {
    await this.database.oidcArtifact.deleteMany({ where: { model: this.model, idHash: hashOidcIdentifier(id) } });
  }

  async revokeByGrantId(grantId: string): Promise<void> {
    const hash = hashOidcIdentifier(grantId);
    await this.database.oidcArtifact.deleteMany({ where: { OR: [{ grantHash: hash }, { model: "Grant", idHash: hash }] } });
  }

  private async findClient(clientId: string): Promise<AdapterPayload | undefined> {
    const connection = await this.database.projectConnection.findUnique({
      where: { clientId },
      select: { clientId: true, clientSecretCiphertext: true, name: true, origin: true, redirectUris: true, enabled: true }
    });
    if (!connection?.enabled) return undefined;
    const redirectUris = stringArray(connection.redirectUris);
    if (!redirectUris.length) return undefined;
    return {
      client_id: connection.clientId,
      client_secret: decryptOidcClientSecret(connection.clientSecretCiphertext),
      client_name: connection.name,
      client_uri: connection.origin,
      redirect_uris: redirectUris,
      grant_types: ["authorization_code"],
      response_types: ["code"],
      application_type: "web",
      token_endpoint_auth_method: "client_secret_basic",
      scope: "openid profile email",
      id_token_signed_response_alg: "ES256"
    };
  }

  private async readArtifact(record: { payloadCiphertext: string; expiresAt: Date | null } | null): Promise<AdapterPayload | undefined> {
    if (!record) return undefined;
    if (record.expiresAt && record.expiresAt <= new Date()) return undefined;
    try {
      return parsePayload(decryptOidcPayload(record.payloadCiphertext));
    } catch {
      return undefined;
    }
  }
}

export async function deleteExpiredOidcArtifacts(
  database: Pick<PrismaClient, "oidcArtifact"> = prisma,
  now = new Date()
): Promise<number> {
  const result = await database.oidcArtifact.deleteMany({ where: { expiresAt: { lte: now } } });
  return result.count;
}

function getProjectAuthorizationContext(payload: AdapterPayload, requireProviderGrantId: boolean): { accountId: string; clientId: string } {
  if (typeof payload.accountId !== "string" || !payload.accountId || typeof payload.clientId !== "string" || !payload.clientId || (requireProviderGrantId && (typeof payload.grantId !== "string" || !payload.grantId))) {
    throw new Error("OIDC artifact authorization is incomplete.");
  }
  return { accountId: payload.accountId, clientId: payload.clientId };
}

function parsePayload(value: string): AdapterPayload {
  const payload: unknown = JSON.parse(value);
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error("Invalid stored OIDC record.");
  return payload as AdapterPayload;
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) return [];
  return value;
}
