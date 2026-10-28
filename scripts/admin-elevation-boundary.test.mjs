import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const adminActions = readFileSync(path.join(repositoryRoot, "apps", "hub", "src", "app", "admin", "actions.ts"), "utf8");
const recoveryActions = readFileSync(path.join(repositoryRoot, "apps", "hub", "src", "app", "recover", "actions.ts"), "utf8");
const administration = readFileSync(path.join(repositoryRoot, "packages", "auth", "src", "administration.ts"), "utf8");
const adminSecurityActions = readFileSync(path.join(repositoryRoot, "apps", "hub", "src", "app", "admin", "security", "actions.ts"), "utf8");
const invitation = readFileSync(path.join(repositoryRoot, "packages", "auth", "src", "account-invitation.ts"), "utf8");
const security = readFileSync(path.join(repositoryRoot, "packages", "auth", "src", "security.ts"), "utf8");

function exportedFunction(source, name) {
  const start = source.indexOf(`export async function ${name}(`);
  assert.ok(start >= 0, `Missing exported function ${name}.`);
  const next = source.indexOf("\nexport async function ", start + 1);
  return source.slice(start, next < 0 ? undefined : next);
}

test("every inline elevated Hub mutation rechecks proof inside its transaction before writes", () => {
  const cases = [
    ["setAccountStateAction", "ACCOUNT_STATE_CHANGE", "transaction.user.updateMany"],
    ["createProjectConnectionAction", "PROJECT_CONNECTION_MANAGE", "transaction.projectConnection.create"],
    ["updateProjectConnectionAction", "PROJECT_CONNECTION_MANAGE", "transaction.projectConnection.update"],
    ["rotateProjectClientSecretAction", "PROJECT_CONNECTION_MANAGE", "compareAndSetProjectConnectionSecret(transaction"],
    ["setProjectConnectionEnabledAction", "PROJECT_CONNECTION_MANAGE", "setProjectConnectionEnabledInTransaction(transaction"],
    ["deleteProjectConnectionAction", "PROJECT_CONNECTION_MANAGE", "deleteProjectConnectionInTransaction(transaction"],
  ];

  for (const [name, scope, write] of cases) {
    const body = exportedFunction(adminActions, name);
    const transaction = body.indexOf("prisma.$transaction(");
    const authorization = body.indexOf(`requireSecurityElevationInTransaction(transaction, actor.user.id, actor.id, "${scope}"`);
    const mutation = body.indexOf(write);
    assert.ok(transaction >= 0 && authorization > transaction && mutation > authorization, `${name} must authorize inside its transaction before ${write}.`);
  }
});

test("account invitation and recovery approval bind elevated proof to their own writes", () => {
  const createAccount = exportedFunction(adminActions, "createAccountAction");
  assert.match(createAccount, /provisionInvitedUserAccount\(actor\.user, actor\.id,/u);

  const invite = exportedFunction(invitation, "provisionInvitedUserAccount");
  const inviteTransaction = invite.indexOf("prisma.$transaction(");
  const inviteAuthorization = invite.indexOf("requireSecurityElevationInTransaction(");
  const inviteWrite = invite.indexOf("transaction.user.create");
  assert.ok(inviteTransaction >= 0 && inviteAuthorization > inviteTransaction && inviteWrite > inviteAuthorization);

  const approveAction = exportedFunction(recoveryActions, "approveRecoveryAction");
  assert.match(approveAction, /approveAccountRecovery\(session\.user, session\.id,/u);
  const approve = exportedFunction(security, "approveAccountRecovery");
  const approvalTransaction = approve.indexOf("prisma.$transaction(");
  const approvalAuthorization = approve.indexOf("requireSecurityElevationInTransaction(");
  const approvalWrite = approve.indexOf("transaction.accountRecoveryRequest.updateMany");
  assert.ok(approvalTransaction >= 0 && approvalAuthorization > approvalTransaction && approvalWrite > approvalAuthorization);
});

test("account state changes require the expected canonical status and current activity flag", () => {
  const body = exportedFunction(adminActions, "setAccountStateAction");
  assert.match(body, /where:\s*accountStateTransitionWhere\(userId, enabled\)/u);
});

test("project access service mutations retain their transactional elevation checks", () => {
  for (const [name, write] of [
    ["grantProjectAccess", "transaction.userProjectGrant.upsert"],
    ["revokeProjectAccess", "transaction.userProjectGrant.updateMany"],
  ]) {
    const body = exportedFunction(administration, name);
    const transaction = body.indexOf("prisma.$transaction(");
    const authorization = body.indexOf("requireSecurityElevationInTransaction(");
    const mutation = body.indexOf(write);
    assert.ok(transaction >= 0 && authorization > transaction && mutation > authorization, `${name} must authorize inside its transaction before ${write}.`);
  }
});

test("ADMIN elevation revocation locks the acting session and revalidates it after the audit write", () => {
  const body = exportedFunction(adminSecurityActions, "revokeElevationAction");
  const transactionStart = body.indexOf("prisma.$transaction(");
  const actorLock = body.indexOf("lockAdminSessionInTransaction(transaction, session.user.id, session.id,");
  const mutation = body.indexOf("transaction.securityElevation.updateMany");
  const audit = body.indexOf("writeAuditLogInTransaction(transaction,");
  const finalCheck = body.indexOf("assertAdminSessionCurrentInTransaction(transaction, session.user.id, session.id,");
  assert.ok(transactionStart >= 0 && actorLock > transactionStart && mutation > actorLock,
    "ADMIN elevation revocation must lock the actor's session before writing");
  assert.ok(audit > mutation && finalCheck > audit,
    "ADMIN elevation revocation must revalidate the actor's session after audit persistence");
});
