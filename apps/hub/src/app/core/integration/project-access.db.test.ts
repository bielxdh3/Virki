import assert from "node:assert/strict";
import { after, beforeEach, test } from "node:test";

import { prisma } from "@bielos/database";

import {
  CoreProjectAccessMutationError,
  revokeCoreProjectAccessRecord,
  setCoreProjectAccessRecord
} from "../projects/access-service";
import { findCoreProjectDetailForPrincipal } from "../projects/read-service";
import {
  cleanCoreIntegrationTestData,
  disconnectCoreIntegrationTestDatabase
} from "./test-database";

let owner: { id: string; role: string };
let admin: { id: string; role: string };
let member: { id: string; role: string };
let secondMember: { id: string; role: string };

beforeEach(async () => {
  await cleanCoreIntegrationTestData();
  [owner, admin, member, secondMember] = await Promise.all([
    createUser("owner@example.invalid", "OWNER"),
    createUser("admin@example.invalid", "ADMIN"),
    createUser("member-a@example.invalid", "MEMBER"),
    createUser("member-b@example.invalid", "MEMBER")
  ]);
});

after(async () => {
  await cleanCoreIntegrationTestData();
  await disconnectCoreIntegrationTestDatabase();
});

test("OWNER grants, changes, and repeats access without duplicate rows", async () => {
  const project = await createProject("owner-access", owner.id);

  const granted = await setCoreProjectAccessRecord(owner, project.id, member.id, "VIEWER");
  const changed = await setCoreProjectAccessRecord(owner, project.id, member.id, "EDITOR");
  const unchanged = await setCoreProjectAccessRecord(owner, project.id, member.id, "EDITOR");

  assert.equal(granted.kind, "granted");
  assert.equal(changed.kind, "changed");
  assert.equal(unchanged.kind, "unchanged");
  assert.equal(granted.accessId, changed.accessId);
  assert.equal(changed.accessId, unchanged.accessId);
  assert.equal(
    await prisma.projectAccess.count({
      where: { projectId: project.id, userId: member.id }
    }),
    1
  );

  const access = await prisma.projectAccess.findUniqueOrThrow({
    where: { userId_projectId: { userId: member.id, projectId: project.id } }
  });
  assert.equal(access.accessLevel, "EDITOR");

  const audits = await prisma.auditLog.findMany({
    where: { resource: "core.project-access" },
    orderBy: { createdAt: "asc" }
  });
  assert.deepEqual(
    audits.map((audit) => audit.eventType),
    ["CORE_PROJECT_ACCESS_GRANTED", "CORE_PROJECT_ACCESS_CHANGED"]
  );

  for (const audit of audits) {
    assertSafeAccessAudit(audit.metadata, [
      project.id,
      member.id,
      granted.accessId,
      "owner@example.invalid",
      "member-a@example.invalid"
    ]);
  }
});

test("OWNER assignment is visible in a fresh persisted project read", async () => {
  const project = await createProject("owner-read-back", owner.id);

  const result = await setCoreProjectAccessRecord(owner, project.id, member.id, "OWNER");
  assert.equal(result.kind, "granted");

  const persisted = await prisma.projectAccess.findUniqueOrThrow({
    where: { userId_projectId: { userId: member.id, projectId: project.id } },
    select: { accessLevel: true }
  });
  assert.equal(persisted.accessLevel, "OWNER");

  const detail = await findCoreProjectDetailForPrincipal(owner, project.id);
  assert.ok(detail?.administrator);
  assert.equal(
    detail.accesses.find((access) => access.user.id === member.id)?.accessLevel,
    "OWNER"
  );

  const refreshedDetail = await findCoreProjectDetailForPrincipal(owner, project.id);
  assert.ok(refreshedDetail?.administrator);
  assert.equal(
    refreshedDetail.accesses.find((access) => access.user.id === member.id)?.accessLevel,
    "OWNER"
  );
});

test("global roles govern access administration independently of project access", async () => {
  const project = await createProject("global-roles", owner.id);
  await setCoreProjectAccessRecord(owner, project.id, admin.id, "OWNER");
  await setCoreProjectAccessRecord(owner, project.id, member.id, "OWNER");

  await setCoreProjectAccessRecord(admin, project.id, secondMember.id, "VIEWER");
  await setCoreProjectAccessRecord(admin, project.id, secondMember.id, "EDITOR");
  await expectAccessMutationRejected(
    setCoreProjectAccessRecord(admin, project.id, secondMember.id, "OWNER")
  );
  await expectAccessMutationRejected(
    setCoreProjectAccessRecord(admin, project.id, member.id, "EDITOR")
  );
  await expectAccessMutationRejected(
    revokeCoreProjectAccessRecord(admin, project.id, member.id)
  );

  await expectAccessMutationRejected(
    setCoreProjectAccessRecord(member, project.id, secondMember.id, "VIEWER")
  );
  await expectAccessMutationRejected(
    revokeCoreProjectAccessRecord(member, project.id, secondMember.id)
  );

  await revokeCoreProjectAccessRecord(admin, project.id, secondMember.id);
  assert.equal(
    await prisma.projectAccess.count({
      where: { projectId: project.id, userId: secondMember.id }
    }),
    0
  );
});

test("persisted actor state, targets, values, and archived projects are revalidated", async () => {
  const project = await createProject("validation", owner.id);
  const archivedProject = await createProject("archived-access", owner.id, "ARCHIVED");
  const inactiveTarget = await createUser("inactive@example.invalid", "MEMBER", false);

  await expectAccessMutationRejected(
    setCoreProjectAccessRecord({ id: owner.id, role: "ADMIN" }, project.id, member.id, "VIEWER")
  );
  await expectAccessMutationRejected(
    setCoreProjectAccessRecord(member, project.id, secondMember.id, "VIEWER")
  );
  await expectAccessMutationRejected(
    setCoreProjectAccessRecord(owner, project.id, inactiveTarget.id, "VIEWER")
  );
  await expectAccessMutationRejected(
    setCoreProjectAccessRecord(owner, archivedProject.id, member.id, "VIEWER")
  );
  await expectAccessMutationRejected(
    setCoreProjectAccessRecord(owner, "missing-project", member.id, "VIEWER")
  );
  await expectAccessMutationRejected(
    setCoreProjectAccessRecord(owner, project.id, "missing-user", "VIEWER")
  );
  await expectAccessMutationRejected(
    setCoreProjectAccessRecord(owner, project.id, member.id, "ADMIN")
  );
  await expectAccessMutationRejected(
    setCoreProjectAccessRecord(owner, "x".repeat(129), member.id, "VIEWER")
  );

  await prisma.user.update({ where: { id: owner.id }, data: { isActive: false } });
  await expectAccessMutationRejected(
    setCoreProjectAccessRecord(owner, project.id, member.id, "VIEWER")
  );
  await expectAccessMutationRejected(
    revokeCoreProjectAccessRecord(owner, project.id, owner.id)
  );
});

test("last active OWNER cannot be demoted or revoked", async () => {
  const project = await createProject("owner-retention", owner.id);

  await expectAccessMutationRejected(
    setCoreProjectAccessRecord(owner, project.id, owner.id, "EDITOR")
  );
  await expectAccessMutationRejected(
    revokeCoreProjectAccessRecord(owner, project.id, owner.id)
  );

  await setCoreProjectAccessRecord(owner, project.id, member.id, "OWNER");
  await setCoreProjectAccessRecord(owner, project.id, owner.id, "EDITOR");

  const activeOwners = await prisma.projectAccess.count({
    where: {
      projectId: project.id,
      accessLevel: "OWNER",
      user: { isActive: true }
    }
  });
  assert.equal(activeOwners, 1);

  await expectAccessMutationRejected(
    revokeCoreProjectAccessRecord(owner, project.id, member.id)
  );

  await prisma.user.update({ where: { id: owner.id }, data: { isActive: false } });
  await expectAccessMutationRejected(
    setCoreProjectAccessRecord(
      { id: admin.id, role: "ADMIN" },
      project.id,
      member.id,
      "EDITOR"
    )
  );
});

test("revoke is scoped to the composite project target and repeated attempts fail", async () => {
  const firstProject = await createProject("first-project", owner.id);
  const secondProject = await createProject("second-project", owner.id);
  await setCoreProjectAccessRecord(owner, firstProject.id, member.id, "VIEWER");
  await setCoreProjectAccessRecord(owner, secondProject.id, member.id, "EDITOR");
  await prisma.auditLog.deleteMany();

  await revokeCoreProjectAccessRecord(owner, firstProject.id, member.id);
  await expectAccessMutationRejected(
    revokeCoreProjectAccessRecord(owner, firstProject.id, member.id)
  );

  assert.equal(
    await prisma.projectAccess.count({
      where: { projectId: firstProject.id, userId: member.id }
    }),
    0
  );
  const retained = await prisma.projectAccess.findUniqueOrThrow({
    where: {
      userId_projectId: { userId: member.id, projectId: secondProject.id }
    }
  });
  assert.equal(retained.accessLevel, "EDITOR");

  const audit = await prisma.auditLog.findFirstOrThrow({
    where: { eventType: "CORE_PROJECT_ACCESS_REVOKED" }
  });
  assertSafeAccessAudit(audit.metadata, [
    firstProject.id,
    secondProject.id,
    member.id,
    "member-a@example.invalid"
  ]);
});

function createUser(
  email: string,
  role: "OWNER" | "ADMIN" | "MEMBER",
  isActive = true
) {
  return prisma.user.create({
    data: { email, role, isActive },
    select: { id: true, role: true }
  });
}

async function createProject(
  slug: string,
  ownerUserId: string,
  status: "ACTIVE" | "ARCHIVED" = "ACTIVE"
) {
  return prisma.project.create({
    data: {
      name: slug,
      slug,
      status,
      visibility: "INTERNAL",
      accesses: {
        create: { userId: ownerUserId, accessLevel: "OWNER" }
      }
    },
    select: { id: true }
  });
}

async function expectAccessMutationRejected(operation: Promise<unknown>): Promise<void> {
  await assert.rejects(operation, (error) => {
    assert.equal(error instanceof CoreProjectAccessMutationError, true);
    assert.equal((error as Error).message, "Core project access mutation rejected.");
    return true;
  });
}

function assertSafeAccessAudit(metadata: unknown, forbiddenValues: string[]): void {
  const serialized = JSON.stringify(metadata);

  for (const value of forbiddenValues) {
    assert.equal(serialized.includes(value), false);
  }

  const keys = Object.keys((metadata ?? {}) as Record<string, unknown>).sort();
  assert.equal(keys.includes("projectRef"), true);
  assert.equal(keys.includes("userRef"), true);
  assert.equal(keys.includes("accessRef"), true);
  assert.equal(
    keys.every((key) => ["accessLevel", "accessRef", "projectRef", "userRef"].includes(key)),
    true
  );
}
