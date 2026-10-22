import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { after, test } from "node:test";
import { encryptOidcClientSecret, encryptOidcPayload, hashOidcIdentifier } from "@virki/auth/oidc-secrets";
import { prisma } from "@virki/database";
import { createTestUser, integrationOptions } from "../../../packages/auth/src/integration-fixtures";
import { PrismaOidcAdapter } from "./adapter";

after(() => prisma.$disconnect());

async function waitForBlockedQuery(blockerPid: number, queryFragment: string): Promise<number> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const blocked = await prisma.$queryRaw<Array<{ pid: number }>>`
      SELECT pid
      FROM pg_stat_activity
      WHERE wait_event_type = 'Lock'
        AND pg_blocking_pids(pid) @> ARRAY[${blockerPid}]::integer[]
        AND query LIKE ${`%${queryFragment}%`}
      LIMIT 1
    `;
    if (blocked[0]) return blocked[0].pid;
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  throw new Error(`Timed out waiting for PostgreSQL lock wait on ${queryFragment}.`);
}

test("grant revocation serializes with a grant-bound token upsert", integrationOptions, async () => {
  const user = await createTestUser({ label: "oidc-grant-revocation" });
  const clientId = `client-${randomUUID()}`;
  const connection = await prisma.projectConnection.create({ data: {
    name: "Grant revocation race",
    slug: clientId,
    origin: "https://project.integration.invalid",
    clientId,
    clientSecretCiphertext: encryptOidcClientSecret(randomBytes(32).toString("base64url")),
    redirectUris: ["https://project.integration.invalid/callback"]
  } });
  await prisma.userProjectGrant.create({ data: { userId: user.id, connectionId: connection.id } });

  const grantId = randomBytes(24).toString("base64url");
  const tokenId = randomBytes(24).toString("base64url");
  const grantHash = hashOidcIdentifier(grantId);
  const tokenIdHash = hashOidcIdentifier(tokenId);
  await prisma.oidcArtifact.create({ data: {
    model: "Grant",
    idHash: grantHash,
    payloadCiphertext: encryptOidcPayload(JSON.stringify({ accountId: user.id, clientId, grantId })),
    expiresAt: new Date(Date.now() + 60_000)
  } });
  const adapter = new PrismaOidcAdapter("AccessToken");
  const payload = { accountId: user.id, clientId, grantId } as never;
  await adapter.upsert(tokenId, payload, 300);

  let blockerPid = 0;
  let locked!: () => void;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => { locked = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const tokenLock = prisma.$transaction(async (transaction) => {
    [{ pid: blockerPid }] = await transaction.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid() AS pid`;
    await transaction.$queryRaw`SELECT "id" FROM "OidcArtifact" WHERE "model" = 'AccessToken' AND "idHash" = ${tokenIdHash} FOR UPDATE`;
    locked();
    await gate;
  }, { timeout: 10_000 });
  await ready;

  const revoke = adapter.revokeByGrantId(grantId).then(() => ({ ok: true as const }), (error: unknown) => ({ ok: false as const, error }));
  let upsert: Promise<{ ok: true } | { ok: false; error: unknown }> | undefined;
  try {
    const revokePid = await waitForBlockedQuery(blockerPid, "OidcArtifact");
    upsert = adapter.upsert(tokenId, payload, 300).then(() => ({ ok: true as const }), (error: unknown) => ({ ok: false as const, error }));
    await waitForBlockedQuery(revokePid, "FOR UPDATE");
  } finally {
    release();
    await tokenLock;
  }
  const revokeOutcome = await revoke;
  assert.equal(revokeOutcome.ok, true);
  assert.ok(upsert);
  const upsertOutcome = await upsert;
  assert.equal(upsertOutcome.ok, false, "token persistence must lose when grant revocation is ordered first");
  assert.equal(await prisma.oidcArtifact.count({ where: { grantHash } }), 0);
  assert.equal(await prisma.oidcArtifact.count({ where: { model: "Grant", idHash: grantHash } }), 0);
});
