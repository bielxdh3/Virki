"use server";

import { randomBytes } from "node:crypto";
import { hashPassword, normalizeEmail, writeAuditLog, hashAuditEmail } from "@bielos/auth";
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
    const now = new Date();
    const user = await prisma.user.create({
      data: {
        email,
        emailNormalized: email,
        displayName: displayName || null,
        passwordHash: await hashPassword(password),
        role: "USER",
        isActive: true,
        accountStatus: "ACTIVE",
        emailVerifiedAt: now
      },
      select: { id: true }
    });
    await writeAuditLog({ eventType: "ACCOUNT_CREATED", result: "SUCCESS", actorUserId: actor.user.id, resource: "account", message: "User account provisioned.", metadata: { targetRef: hashOidcIdentifier(user.id), emailRef: hashAuditEmail(email) } });
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
    const changed = await prisma.user.updateMany({
      where: { id: userId, role: "USER" },
      data: { isActive: enabled, accountStatus: enabled ? "ACTIVE" : "INACTIVE" }
    });
    if (changed.count !== 1) throw new Error("Account was not found.");
    if (!enabled) await prisma.$transaction([
      prisma.session.updateMany({ where: { userId, revokedAt: null }, data: { revokedAt: now } }),
      prisma.securityElevation.updateMany({ where: { userId, status: { in: ["PENDING", "ACTIVE"] } }, data: { status: "REVOKED", revokedAt: now } }),
      prisma.oidcArtifact.deleteMany({ where: { accountIdHash: hashOidcIdentifier(userId) } })
    ]);
    await writeAuditLog({ eventType: "ACCOUNT_STATE_CHANGED", result: "SUCCESS", actorUserId: actor.user.id, resource: "account", message: enabled ? "User account enabled." : "User account disabled and sessions revoked.", metadata: { targetRef: hashOidcIdentifier(userId), enabled } });
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
    const user = await prisma.user.findFirst({ where: { id: userId, isActive: true, accountStatus: "ACTIVE" }, select: { id: true } });
    const connection = await prisma.projectConnection.findFirst({ where: { id: connectionId, enabled: true }, select: { id: true } });
    if (!user || !connection) throw new Error("Invalid access grant.");
    await prisma.userProjectGrant.upsert({
      where: { userId_connectionId: { userId, connectionId } },
      create: { userId, connectionId, grantedByUserId: actor.user.id },
      update: { revokedAt: null, grantedByUserId: actor.user.id }
    });
    await writeAuditLog({ eventType: "PROJECT_ACCESS_GRANTED", result: "SUCCESS", actorUserId: actor.user.id, resource: "project.access", message: "Project access granted.", metadata: { userRef: hashOidcIdentifier(userId), connectionRef: hashOidcIdentifier(connectionId) } });
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
    await prisma.$transaction([
      prisma.userProjectGrant.update({ where: { id: grant.id }, data: { revokedAt: new Date() } }),
      prisma.oidcArtifact.deleteMany({ where: { clientIdHash: hashOidcIdentifier(grant.connection.clientId), accountIdHash: hashOidcIdentifier(grant.userId) } })
    ]);
    await writeAuditLog({ eventType: "PROJECT_ACCESS_REVOKED", result: "SUCCESS", actorUserId: actor.user.id, resource: "project.access", message: "Project access revoked and OIDC artifacts cleared.", metadata: { userRef: hashOidcIdentifier(grant.userId), connectionRef: hashOidcIdentifier(grant.connectionId) } });
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
      redirectUris: readFormString(formData, "redirectUris")
    });
    const clientId = `biel_${randomBytes(18).toString("base64url")}`;
    const secret = randomBytes(48).toString("base64url");
    const created = await prisma.projectConnection.create({
      data: {
        ...connection,
        clientId,
        clientSecretCiphertext: encryptOidcClientSecret(secret),
        redirectUris: connection.redirectUris,
        createdByUserId: actor.user.id
      },
      select: { id: true }
    });
    await writeAuditLog({ eventType: "PROJECT_CONNECTION_CREATED", result: "SUCCESS", actorUserId: actor.user.id, resource: "project.connection", message: "External OIDC connection created.", metadata: { connectionRef: hashOidcIdentifier(created.id), clientRef: hashOidcIdentifier(clientId) } });
    revalidatePath("/admin/connections");
    return { status: "created", clientId, secret };
  } catch (error) {
    if (error instanceof ConnectionInputError) return { status: "error" };
    return { status: "error" };
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
    await prisma.$transaction([
      prisma.projectConnection.update({ where: { id: connectionId }, data: { clientSecretCiphertext: encryptOidcClientSecret(secret) } }),
      prisma.oidcArtifact.deleteMany({ where: { clientIdHash: hashOidcIdentifier(connection.clientId) } })
    ]);
    await writeAuditLog({ eventType: "PROJECT_CONNECTION_UPDATED", result: "SUCCESS", actorUserId: actor.user.id, resource: "project.connection", message: "Client secret rotated and outstanding OIDC artifacts cleared.", metadata: { connectionRef: hashOidcIdentifier(connection.id), clientRef: hashOidcIdentifier(connection.clientId) } });
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
    const connection = await prisma.projectConnection.update({ where: { id: connectionId }, data: { enabled }, select: { id: true, clientId: true } });
    if (!enabled) await prisma.oidcArtifact.deleteMany({ where: { clientIdHash: hashOidcIdentifier(connection.clientId) } });
    await writeAuditLog({ eventType: "PROJECT_CONNECTION_UPDATED", result: "SUCCESS", actorUserId: actor.user.id, resource: "project.connection", message: enabled ? "External connection enabled." : "External connection disabled and OIDC artifacts cleared.", metadata: { connectionRef: hashOidcIdentifier(connection.id) } });
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
    const connectionId = readFormString(formData, "connectionId");
    const connection = await prisma.projectConnection.findUnique({ where: { id: connectionId }, select: { id: true, clientId: true } });
    if (!connection) throw new Error("Connection was not found.");
    await prisma.$transaction([
      prisma.oidcArtifact.deleteMany({ where: { clientIdHash: hashOidcIdentifier(connection.clientId) } }),
      prisma.projectConnection.delete({ where: { id: connectionId } })
    ]);
    await writeAuditLog({ eventType: "PROJECT_CONNECTION_REVOKED", result: "SUCCESS", actorUserId: actor.user.id, resource: "project.connection", message: "External connection deleted and OIDC artifacts cleared.", metadata: { connectionRef: hashOidcIdentifier(connection.id) } });
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
