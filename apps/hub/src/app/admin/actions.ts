"use server";

import { randomBytes } from "node:crypto";
import { hashPassword, normalizeEmail, hashAuditEmail, writeAuditLogInTransaction } from "@bielos/auth";
import { revokeUserAuthenticationProofsInTransaction } from "@bielos/auth/security";
import { encryptOidcClientSecret, hashOidcIdentifier } from "@bielos/auth/oidc-secrets";
import { requireSecurityElevation } from "@bielos/auth/administration";
import { prisma } from "@bielos/database";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { requireAdminMutation, readFormRawString, readFormString } from "../../lib/admin-mutation";
import { ConnectionInputError, validateProjectConnectionInput } from "../../lib/connection-policy";

export type ConnectionActionState = {
  status: "idle" | "error" | "created" | "rotated";
  clientId?: string;
  secret?: string;
};

export async function createAccountAction(formData: FormData): Promise<void> {
  const actor = await requireAdminMutation(formData, "admin-account-create");
  try {
    await requireSecurityElevation(actor.user.id, actor.id, "ACCOUNT_STATE_CHANGE");
    const email = normalizeEmail(readFormString(formData, "email"));
    const password = readFormRawString(formData, "password");
    const displayName = readFormString(formData, "displayName");
    if (!/^\S+@\S+\.\S+$/u.test(email) || password.length < 12 || password.length > 256 || displayName.length > 80) throw new Error("Invalid account input.");
    const passwordHash = await hashPassword(password);
    await prisma.$transaction(async (transaction) => {
      const user = await transaction.user.create({
        data: {
          email,
          emailNormalized: email,
          displayName: displayName || null,
          passwordHash,
          role: "USER",
          isActive: true,
          accountStatus: "ACTIVE",
          emailVerifiedAt: null
        },
        select: { id: true }
      });
      await writeAuditLogInTransaction(transaction, { eventType: "ACCOUNT_CREATED", result: "SUCCESS", actorUserId: actor.user.id, resource: "account", message: "User account provisioned.", metadata: { targetRef: hashOidcIdentifier(user.id), emailRef: hashAuditEmail(email) } });
    });
    revalidatePath("/admin/accounts");
    redirect("/admin/accounts?status=created");
  } catch (error) {
    if (isRedirect(error)) throw error;
    redirect("/admin/accounts?error=create");
  }
}

export async function setAccountStateAction(formData: FormData): Promise<void> {
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
      await writeAuditLogInTransaction(transaction, { eventType: "ACCOUNT_STATE_CHANGED", result: "SUCCESS", actorUserId: actor.user.id, resource: "account", message: enabled ? "User account enabled." : "User account disabled and sessions revoked.", metadata: { targetRef: hashOidcIdentifier(userId), enabled } });
    });
    revalidatePath("/admin/accounts");
    redirect("/admin/accounts?status=updated");
  } catch (error) {
    if (isRedirect(error)) throw error;
    redirect("/admin/accounts?error=update");
  }
}

export async function grantProjectAccessAction(formData: FormData): Promise<void> {
  const actor = await requireAdminMutation(formData, "admin-project-access-grant");
  try {
    await requireSecurityElevation(actor.user.id, actor.id, "PROJECT_ACCESS_CHANGE");
    const userId = readFormString(formData, "userId");
    const connectionId = readFormString(formData, "connectionId");
    const user = await prisma.user.findFirst({ where: { id: userId, role: "USER", isActive: true, accountStatus: "ACTIVE" }, select: { id: true } });
    const connection = await prisma.projectConnection.findFirst({ where: { id: connectionId, enabled: true }, select: { id: true } });
    if (!user || !connection) throw new Error("Invalid access grant.");
    await prisma.$transaction(async (transaction) => {
      await transaction.userProjectGrant.upsert({
        where: { userId_connectionId: { userId, connectionId } },
        create: { userId, connectionId, grantedByUserId: actor.user.id },
        update: { revokedAt: null, grantedByUserId: actor.user.id }
      });
      await writeAuditLogInTransaction(transaction, { eventType: "PROJECT_ACCESS_GRANTED", result: "SUCCESS", actorUserId: actor.user.id, resource: "project.access", message: "Project access granted.", metadata: { userRef: hashOidcIdentifier(userId), connectionRef: hashOidcIdentifier(connectionId) } });
    });
    revalidatePath("/admin/access");
    redirect("/admin/access?status=granted");
  } catch (error) {
    if (isRedirect(error)) throw error;
    redirect("/admin/access?error=grant");
  }
}

export async function revokeProjectAccessAction(formData: FormData): Promise<void> {
  const actor = await requireAdminMutation(formData, "admin-project-access-revoke");
  try {
    await requireSecurityElevation(actor.user.id, actor.id, "PROJECT_ACCESS_CHANGE");
    const grantId = readFormString(formData, "grantId");
    const grant = await prisma.userProjectGrant.findUnique({ where: { id: grantId }, select: { id: true, userId: true, connectionId: true, connection: { select: { clientId: true } } } });
    if (!grant) throw new Error("Invalid access grant.");
    await prisma.$transaction(async (transaction) => {
      await transaction.userProjectGrant.update({ where: { id: grant.id }, data: { revokedAt: new Date() } });
      await transaction.oidcArtifact.deleteMany({ where: { clientIdHash: hashOidcIdentifier(grant.connection.clientId), accountIdHash: hashOidcIdentifier(grant.userId) } });
      await writeAuditLogInTransaction(transaction, { eventType: "PROJECT_ACCESS_REVOKED", result: "SUCCESS", actorUserId: actor.user.id, resource: "project.access", message: "Project access revoked and OIDC artifacts cleared.", metadata: { userRef: hashOidcIdentifier(grant.userId), connectionRef: hashOidcIdentifier(grant.connectionId) } });
    });
    revalidatePath("/admin/access");
    redirect("/admin/access?status=revoked");
  } catch (error) {
    if (isRedirect(error)) throw error;
    redirect("/admin/access?error=revoke");
  }
}

export async function createProjectConnectionAction(_state: ConnectionActionState, formData: FormData): Promise<ConnectionActionState> {
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
    if (error instanceof ConnectionInputError) return { status: "error" };
    return { status: "error" };
  }
}

export async function updateProjectConnectionAction(formData: FormData): Promise<void> {
  const actor = await requireAdminMutation(formData, "admin-project-connection-update");
  try {
    await requireSecurityElevation(actor.user.id, actor.id, "PROJECT_CONNECTION_MANAGE");
    const connectionId = readFormString(formData, "connectionId");
    const connection = validateProjectConnectionInput({
      name: readFormString(formData, "name"),
      slug: readFormString(formData, "slug"),
      origin: readFormString(formData, "origin"),
      launchUrl: readFormString(formData, "launchUrl"),
      redirectUris: readFormString(formData, "redirectUris")
    });
    await prisma.$transaction(async (transaction) => {
      const existing = await transaction.projectConnection.findUnique({
        where: { id: connectionId },
        select: { id: true, clientId: true, origin: true, redirectUris: true }
      });
      if (!existing) throw new Error("Connection was not found.");
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
    }, { isolationLevel: "Serializable" });
    revalidatePath("/admin/connections");
    revalidatePath("/");
    redirect("/admin/connections?status=updated");
  } catch (error) {
    if (error instanceof ConnectionInputError) redirect("/admin/connections?error=configuration");
    if (isRedirect(error)) throw error;
    redirect("/admin/connections?error=update");
  }
}

export async function rotateProjectClientSecretAction(_state: ConnectionActionState, formData: FormData): Promise<ConnectionActionState> {
  const actor = await requireAdminMutation(formData, "admin-project-connection-rotate");
  try {
    await requireSecurityElevation(actor.user.id, actor.id, "PROJECT_CONNECTION_MANAGE");
    const connectionId = readFormString(formData, "connectionId");
    const connection = await prisma.projectConnection.findUnique({ where: { id: connectionId }, select: { id: true, clientId: true, enabled: true } });
    if (!connection || !connection.enabled) return { status: "error" };
    const secret = randomBytes(48).toString("base64url");
    await prisma.$transaction(async (transaction) => {
      await transaction.projectConnection.update({ where: { id: connectionId }, data: { clientSecretCiphertext: encryptOidcClientSecret(secret) } });
      await transaction.oidcArtifact.deleteMany({ where: { clientIdHash: hashOidcIdentifier(connection.clientId) } });
      await writeAuditLogInTransaction(transaction, { eventType: "PROJECT_CONNECTION_UPDATED", result: "SUCCESS", actorUserId: actor.user.id, resource: "project.connection", message: "Client secret rotated and outstanding OIDC artifacts cleared.", metadata: { connectionRef: hashOidcIdentifier(connection.id), clientRef: hashOidcIdentifier(connection.clientId) } });
    });
    revalidatePath("/admin/connections");
    return { status: "rotated", clientId: connection.clientId, secret };
  } catch {
    return { status: "error" };
  }
}

export async function setProjectConnectionEnabledAction(formData: FormData): Promise<void> {
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
    redirect("/admin/connections?error=update");
  }
}

export async function deleteProjectConnectionAction(formData: FormData): Promise<void> {
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
    redirect("/admin/connections?error=delete");
  }
}

function isRedirect(error: unknown): boolean {
  return Boolean(error && typeof error === "object" && "digest" in error && String((error as { digest?: unknown }).digest).startsWith("NEXT_REDIRECT"));
}
