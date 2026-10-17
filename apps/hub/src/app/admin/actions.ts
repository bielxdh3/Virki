"use server";

import { withHubAuditRequest } from "../../lib/audit-request";

import { randomBytes } from "node:crypto";
import { normalizeEmail, writeAuditLogInTransaction } from "@virki/auth";
import { provisionInvitedUserAccount } from "@virki/auth/account-invitation";
import { revokeUserAuthenticationProofsInTransaction } from "@virki/auth/security";
import { encryptOidcClientSecret, hashOidcIdentifier } from "@virki/auth/oidc-secrets";
import { AdministrationMutationError, grantProjectAccess, revokeProjectAccess, requireSecurityElevation } from "@virki/auth/administration";
import { prisma } from "@virki/database";
import { revalidatePath } from "next/cache";
import { headers } from "next/headers";
import { recordSecurityDenial } from "../../lib/audit-denial";
import { redirect } from "next/navigation";
import { requireAdminMutation, readFormRawString, readFormString } from "../../lib/admin-mutation";
import { compareAndSetProjectConnectionSecret } from "../../lib/connection-secret-rotation";
import { ConnectionInputError, projectConnectionConfigurationRevision, validateProjectConnectionInput } from "../../lib/connection-policy";

export type ConnectionActionState = {
  status: "idle" | "error" | "created" | "rotated";
  clientId?: string;
  secret?: string;
};

export type ConnectionEditDraft = {
  name: string;
  slug: string;
  origin: string;
  launchUrl: string;
  redirectUris: string;
  expectedRevision: string;
};

export type ConnectionEditActionState =
  | { status: "idle" }
  | { status: "error" | "invalid" | "authorization" | "elevation-required" | "saved"; draft: ConnectionEditDraft }
  | {
      status: "conflict";
      draft: ConnectionEditDraft;
      latest: {
        name: string;
        slug: string;
        origin: string;
        launchUrl: string | null;
        redirectUris: string[];
        configurationRevision: string;
      };
    };

export async function createAccountAction(formData: FormData): Promise<void> {
  return withHubAuditRequest(async () => {
  const actor = await requireAdminMutation(formData, "admin-account-create");
  try {
    await requireSecurityElevation(actor.user.id, actor.id, "ACCOUNT_STATE_CHANGE");
    const email = normalizeEmail(readFormString(formData, "email"));
    const displayName = readFormString(formData, "displayName");
    if (!/^\S+@\S+\.\S+$/u.test(email) || displayName.length > 80) throw new Error("Invalid account input.");
    await provisionInvitedUserAccount(actor.user, { email, displayName: displayName || null });
    revalidatePath("/admin/accounts");
    redirect("/admin/accounts?status=created");
  } catch (error) {
    if (isRedirect(error)) throw error;
    await recordSecurityDenial(await headers(), "admin-mutation", "rejected", actor);
    redirect("/admin/accounts?error=create");
  }
  });
}

export async function setAccountStateAction(formData: FormData): Promise<void> {
  return withHubAuditRequest(async () => {
  const actor = await requireAdminMutation(formData, "admin-account-state");
  try {
    await requireSecurityElevation(actor.user.id, actor.id, "ACCOUNT_STATE_CHANGE");
    const userId = readFormString(formData, "userId");
    const enabled = readFormString(formData, "enabled") === "true";
    const now = new Date();
    await prisma.$transaction(async (transaction) => {
      const changed = await transaction.user.updateMany({
        where: { id: userId, role: "USER" },
        data: { isActive: enabled, accountStatus: enabled ? "ACTIVE" : "INACTIVE" }
      });
      if (changed.count !== 1) throw new Error("Account was not found.");
      if (!enabled) {
        await transaction.session.updateMany({ where: { userId, revokedAt: null }, data: { revokedAt: now } });
        await transaction.securityElevation.updateMany({ where: { userId, status: { in: ["PENDING", "ACTIVE"] } }, data: { status: "REVOKED", revokedAt: now } });
        await revokeUserAuthenticationProofsInTransaction(transaction, userId, now);
        await transaction.oidcArtifact.deleteMany({ where: { accountIdHash: hashOidcIdentifier(userId) } });
      }
      await writeAuditLogInTransaction(transaction, { eventType: "ACCOUNT_STATE_CHANGED", result: "SUCCESS", actorUserId: actor.user.id, resource: "account", message: enabled ? "User account enabled." : "User account disabled and sessions revoked.", actorRole: "ADMIN", after: { enabled, accountStatus: enabled ? "ACTIVE" : "INACTIVE" }, metadata: { targetRef: hashOidcIdentifier(userId), enabled } });
    });
    revalidatePath("/admin/accounts");
    redirect("/admin/accounts?status=updated");
  } catch (error) {
    if (isRedirect(error)) throw error;
    await recordSecurityDenial(await headers(), "admin-mutation", "rejected", actor);
    redirect("/admin/accounts?error=update");
  }
  });
}

export async function grantProjectAccessAction(formData: FormData): Promise<void> {
  return withHubAuditRequest(async () => {
  const actor = await requireAdminMutation(formData, "admin-project-access-grant");
  try {
    await requireSecurityElevation(actor.user.id, actor.id, "PROJECT_ACCESS_CHANGE");
    const userId = readFormString(formData, "userId");
    const connectionId = readFormString(formData, "connectionId");
    await grantProjectAccess(actor.user, actor.id, userId, connectionId);
    revalidatePath("/admin/access");
    redirect("/admin/access?status=granted");
  } catch (error) {
    if (isRedirect(error)) throw error;
    await recordSecurityDenial(await headers(), "admin-mutation", "rejected", actor);
    redirect("/admin/access?error=grant");
  }
  });
}

export async function revokeProjectAccessAction(formData: FormData): Promise<void> {
  return withHubAuditRequest(async () => {
  const actor = await requireAdminMutation(formData, "admin-project-access-revoke");
  try {
    await requireSecurityElevation(actor.user.id, actor.id, "PROJECT_ACCESS_CHANGE");
    const grantId = readFormString(formData, "grantId");
    await revokeProjectAccess(actor.user, actor.id, grantId);
    revalidatePath("/admin/access");
    redirect("/admin/access?status=revoked");
  } catch (error) {
    if (isRedirect(error)) throw error;
    await recordSecurityDenial(await headers(), "admin-mutation", "rejected", actor);
    redirect("/admin/access?error=revoke");
  }
  });
}

export async function createProjectConnectionAction(_state: ConnectionActionState, formData: FormData): Promise<ConnectionActionState> {
  return withHubAuditRequest(async () => {
  const actor = await requireAdminMutation(formData, "admin-project-connection-create");
  try {
    await requireSecurityElevation(actor.user.id, actor.id, "PROJECT_CONNECTION_MANAGE");
    const connection = validateProjectConnectionInput({
      name: readFormString(formData, "name"),
      slug: readFormString(formData, "slug"),
      origin: readFormString(formData, "origin"),
      launchUrl: readFormString(formData, "launchUrl"),
      redirectUris: readFormString(formData, "redirectUris")
    });
    const clientId = `biel_${randomBytes(18).toString("base64url")}`;
    const secret = randomBytes(48).toString("base64url");
    await prisma.$transaction(async (transaction) => {
      const created = await transaction.projectConnection.create({
        data: {
          ...connection,
          clientId,
          clientSecretCiphertext: encryptOidcClientSecret(secret),
          redirectUris: connection.redirectUris,
          createdByUserId: actor.user.id
        },
        select: { id: true }
      });
      await writeAuditLogInTransaction(transaction, { eventType: "PROJECT_CONNECTION_CREATED", result: "SUCCESS", actorUserId: actor.user.id, resource: "project.connection", message: "External OIDC connection created.", metadata: { connectionRef: hashOidcIdentifier(created.id), clientRef: hashOidcIdentifier(clientId) } });
    });
    revalidatePath("/admin/connections");
    return { status: "created", clientId, secret };
  } catch (error) {
    await recordSecurityDenial(await headers(), "admin-connection-create", "rejected", actor);
    if (error instanceof ConnectionInputError) return { status: "error" };
    return { status: "error" };
  }
  });
}

export async function updateProjectConnectionAction(_state: ConnectionEditActionState, formData: FormData): Promise<ConnectionEditActionState> {
  return withHubAuditRequest(async () => {
  const draft = {
    name: readFormRawString(formData, "name"),
    slug: readFormRawString(formData, "slug"),
    origin: readFormRawString(formData, "origin"),
    launchUrl: readFormRawString(formData, "launchUrl"),
    redirectUris: readFormRawString(formData, "redirectUris"),
    expectedRevision: readFormRawString(formData, "expectedRevision")
  };
  let actor: Awaited<ReturnType<typeof requireAdminMutation>>;
  try {
    actor = await requireAdminMutation(formData, "admin-project-connection-update");
  } catch (error) {
    if (isForbidden(error)) return { status: "authorization", draft };
    throw error;
  }
  try {
    await requireSecurityElevation(actor.user.id, actor.id, "PROJECT_CONNECTION_MANAGE");
    const connectionId = readFormString(formData, "connectionId");
    const connection = validateProjectConnectionInput({
      name: draft.name,
      slug: draft.slug,
      origin: draft.origin,
      launchUrl: draft.launchUrl,
      redirectUris: draft.redirectUris
    });
    const result = await prisma.$transaction(async (transaction) => {
      const existing = await transaction.projectConnection.findUnique({
        where: { id: connectionId },
        select: { id: true, clientId: true, name: true, slug: true, origin: true, launchUrl: true, redirectUris: true }
      });
      if (!existing) throw new Error("Connection was not found.");
      const latestRedirectUris = (Array.isArray(existing.redirectUris) ? existing.redirectUris : []).filter((uri): uri is string => typeof uri === "string");
      const latestRevision = projectConnectionConfigurationRevision({ ...existing, redirectUris: latestRedirectUris });
      if (latestRevision !== draft.expectedRevision) {
        return {
          saved: false as const,
          latest: { ...existing, redirectUris: latestRedirectUris, configurationRevision: latestRevision }
        };
      }
      const redirectUrisChanged = JSON.stringify(existing.redirectUris) !== JSON.stringify(connection.redirectUris);
      const originChanged = existing.origin !== connection.origin;
      const oidcSettingsChanged = originChanged || redirectUrisChanged;
      await transaction.projectConnection.update({ where: { id: connectionId }, data: connection });
      if (oidcSettingsChanged) {
        await transaction.oidcArtifact.deleteMany({ where: { clientIdHash: hashOidcIdentifier(existing.clientId) } });
      }
      await writeAuditLogInTransaction(transaction, {
        eventType: "PROJECT_CONNECTION_UPDATED",
        result: "SUCCESS",
        actorUserId: actor.user.id,
        resource: "project.connection",
        message: oidcSettingsChanged ? "External OIDC connection settings updated and outstanding artifacts cleared." : "External project connection updated.",
        metadata: {
          connectionRef: hashOidcIdentifier(existing.id),
          originChanged,
          redirectUrisChanged,
          launchUrlConfigured: Boolean(connection.launchUrl)
        }
      });
      return { saved: true as const };
    }, { isolationLevel: "Serializable" });
    if (!result.saved) {
      return {
        status: "conflict",
        draft,
        latest: {
          name: result.latest.name,
          slug: result.latest.slug,
          origin: result.latest.origin,
          launchUrl: result.latest.launchUrl,
          redirectUris: result.latest.redirectUris,
          configurationRevision: result.latest.configurationRevision
        }
      };
    }
    revalidatePath("/admin/connections");
    revalidatePath("/");
    return {
      status: "saved",
      draft: {
        ...draft,
        expectedRevision: projectConnectionConfigurationRevision({
          id: connectionId,
          name: connection.name,
          slug: connection.slug,
          origin: connection.origin,
          launchUrl: connection.launchUrl,
          redirectUris: connection.redirectUris
        })
      }
    };
  } catch (error) {
    if (isRedirect(error)) throw error;
    await recordSecurityDenial(await headers(), "admin-mutation", "rejected", actor);
    if (error instanceof AdministrationMutationError) return { status: "elevation-required", draft };
    if (error instanceof ConnectionInputError) return { status: "invalid", draft };
    return { status: "error", draft };
  }
  });
}

export async function rotateProjectClientSecretAction(_state: ConnectionActionState, formData: FormData): Promise<ConnectionActionState> {
  return withHubAuditRequest(async () => {
  const actor = await requireAdminMutation(formData, "admin-project-connection-rotate");
  try {
    await requireSecurityElevation(actor.user.id, actor.id, "PROJECT_CONNECTION_MANAGE");
    const connectionId = readFormString(formData, "connectionId");
    const connection = await prisma.projectConnection.findUnique({ where: { id: connectionId }, select: { id: true, clientId: true, enabled: true, clientSecretCiphertext: true } });
    if (!connection || !connection.enabled) return { status: "error" };
    const secret = randomBytes(48).toString("base64url");
    await prisma.$transaction(async (transaction) => {
      const rotated = await compareAndSetProjectConnectionSecret(transaction, connection, encryptOidcClientSecret(secret));
      if (!rotated) throw new Error("Project connection changed before secret rotation completed.");
      await transaction.oidcArtifact.deleteMany({ where: { clientIdHash: hashOidcIdentifier(connection.clientId) } });
      await writeAuditLogInTransaction(transaction, { eventType: "PROJECT_CONNECTION_UPDATED", result: "SUCCESS", actorUserId: actor.user.id, resource: "project.connection", message: "Client secret rotated and outstanding OIDC artifacts cleared.", metadata: { connectionRef: hashOidcIdentifier(connection.id), clientRef: hashOidcIdentifier(connection.clientId) } });
    });
    revalidatePath("/admin/connections");
    return { status: "rotated", clientId: connection.clientId, secret };
  } catch {
    await recordSecurityDenial(await headers(), "admin-connection-secret", "rejected", actor);
    return { status: "error" };
  }
  });
}

export async function setProjectConnectionEnabledAction(formData: FormData): Promise<void> {
  return withHubAuditRequest(async () => {
  const actor = await requireAdminMutation(formData, "admin-project-connection-state");
  try {
    await requireSecurityElevation(actor.user.id, actor.id, "PROJECT_CONNECTION_MANAGE");
    const connectionId = readFormString(formData, "connectionId");
    const enabled = readFormString(formData, "enabled") === "true";
    await prisma.$transaction(async (transaction) => {
      const connection = await transaction.projectConnection.update({ where: { id: connectionId }, data: { enabled }, select: { id: true, clientId: true } });
      if (!enabled) await transaction.oidcArtifact.deleteMany({ where: { clientIdHash: hashOidcIdentifier(connection.clientId) } });
      await writeAuditLogInTransaction(transaction, { eventType: "PROJECT_CONNECTION_UPDATED", result: "SUCCESS", actorUserId: actor.user.id, resource: "project.connection", message: enabled ? "External connection enabled." : "External connection disabled and OIDC artifacts cleared.", metadata: { connectionRef: hashOidcIdentifier(connection.id) } });
    });
    revalidatePath("/admin/connections");
    redirect("/admin/connections?status=updated");
  } catch (error) {
    if (isRedirect(error)) throw error;
    await recordSecurityDenial(await headers(), "admin-mutation", "rejected", actor);
    redirect("/admin/connections?error=update");
  }
  });
}

export async function deleteProjectConnectionAction(formData: FormData): Promise<void> {
  return withHubAuditRequest(async () => {
  const actor = await requireAdminMutation(formData, "admin-project-connection-delete");
  try {
    await requireSecurityElevation(actor.user.id, actor.id, "PROJECT_CONNECTION_MANAGE");
    if (readFormString(formData, "confirmDelete") !== "yes") throw new Error("Explicit confirmation required.");
    const connectionId = readFormString(formData, "connectionId");
    const connection = await prisma.projectConnection.findUnique({ where: { id: connectionId }, select: { id: true, clientId: true } });
    if (!connection) throw new Error("Connection was not found.");
    await prisma.$transaction(async (transaction) => {
      await transaction.oidcArtifact.deleteMany({ where: { clientIdHash: hashOidcIdentifier(connection.clientId) } });
      await transaction.projectConnection.delete({ where: { id: connectionId } });
      await writeAuditLogInTransaction(transaction, { eventType: "PROJECT_CONNECTION_REVOKED", result: "SUCCESS", actorUserId: actor.user.id, resource: "project.connection", message: "External connection deleted and OIDC artifacts cleared.", metadata: { connectionRef: hashOidcIdentifier(connection.id) } });
    });
    revalidatePath("/admin/connections");
    redirect("/admin/connections?status=deleted");
  } catch (error) {
    if (isRedirect(error)) throw error;
    await recordSecurityDenial(await headers(), "admin-mutation", "rejected", actor);
    redirect("/admin/connections?error=delete");
  }
  });
}

function isRedirect(error: unknown): boolean {
  return Boolean(error && typeof error === "object" && "digest" in error && String((error as { digest?: unknown }).digest).startsWith("NEXT_REDIRECT"));
}

function isForbidden(error: unknown): boolean {
  return Boolean(error && typeof error === "object" && "digest" in error && (error as { digest?: unknown }).digest === "NEXT_HTTP_ERROR_FALLBACK;403");
}
