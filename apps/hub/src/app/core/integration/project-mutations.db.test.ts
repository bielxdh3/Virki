import assert from "node:assert/strict";
import { after, beforeEach, test } from "node:test";

import { prisma } from "@bielos/database";

import {
  archiveCoreProjectRecord,
  CoreProjectMutationError,
  createCoreProjectRecord,
  updateCoreProjectRecord
} from "../projects/mutation-service";
import type { CoreProjectFields } from "../projects/validation";
import {
  cleanCoreIntegrationTestData,
  disconnectCoreIntegrationTestDatabase
} from "./test-database";

let owner: { id: string; role: string };
let admin: { id: string; role: string };
let member: { id: string; role: string };

beforeEach(async () => {
  await cleanCoreIntegrationTestData();
  [owner, admin, member] = await Promise.all([
    createUser("owner@example.invalid", "OWNER"),
    createUser("admin@example.invalid", "ADMIN"),
    createUser("member-a@example.invalid", "MEMBER")
  ]);
});

after(async () => {
  await cleanCoreIntegrationTestData();
  await disconnectCoreIntegrationTestDatabase();
});

test("OWNER and ADMIN create normalized projects with owner access and sanitized audits", async () => {
  const ownerProject = await createCoreProjectRecord(
    owner,
    validFields("Owner Project", "  owner-project  ", "private owner description")
  );
  const adminProject = await createCoreProjectRecord(
    admin,
    validFields("Admin Project", "admin-project", "private admin description")
  );

  const projects = await prisma.project.findMany({
    where: { id: { in: [ownerProject.id, adminProject.id] } },
    include: { accesses: true },
    orderBy: { slug: "asc" }
  });

  assert.deepEqual(projects.map((project) => project.slug), ["admin-project", "owner-project"]);
  assert.equal(
    projects.every(
      (project) =>
        project.accesses.length === 1 && project.accesses[0]?.accessLevel === "OWNER"
    ),
    true
  );

  const audits = await prisma.auditLog.findMany({
    where: { eventType: "CORE_PROJECT_CREATED" },
    orderBy: { createdAt: "asc" }
  });
  assert.equal(audits.length, 2);

  for (const audit of audits) {
    assertSafeProjectAudit(audit.metadata, [
      "private owner description",
      "private admin description",
      "owner@example.invalid",
      "admin@example.invalid",
      "owner-project",
      "admin-project"
    ]);
  }
});

test("creation rejects unauthorized actors, crafted roles, invalid fields, and duplicate slugs", async () => {
  await expectProjectMutationRejected(
    createCoreProjectRecord(member, validFields("Member Project", "member-project"))
  );
  await expectProjectMutationRejected(
    createCoreProjectRecord(
      { id: owner.id, role: "ADMIN" },
      validFields("Forged Role", "forged-role")
    )
  );

  const invalidFields: CoreProjectFields[] = [
    { ...validFields("Invalid", "invalid-visibility"), visibility: "PRIVATE" },
    { ...validFields("Invalid", "invalid-status"), status: "ARCHIVED" },
    validFields("Invalid", "Uppercase-Slug"),
    validFields("x".repeat(81), "long-name"),
    validFields("Long Description", "long-description", "x".repeat(501))
  ];

  for (const fields of invalidFields) {
    await expectProjectMutationRejected(createCoreProjectRecord(owner, fields));
  }

  await createCoreProjectRecord(owner, validFields("Unique", "duplicate-slug"));
  await expectProjectMutationRejected(
    createCoreProjectRecord(admin, validFields("Duplicate", "duplicate-slug"))
  );

  assert.equal(await prisma.project.count(), 1);
});

test("authorized edits preserve access while invalid, member, crafted, and archived edits fail", async () => {
  const project = await createCoreProjectRecord(
    owner,
    validFields("Editable", "editable-project")
  );
  await prisma.auditLog.deleteMany();

  await updateCoreProjectRecord(
    admin,
    project.id,
    validFields("Updated", "updated-project", "private updated description", "SENSITIVE", "PAUSED")
  );

  const updated = await prisma.project.findUniqueOrThrow({
    where: { id: project.id },
    include: { accesses: true }
  });
  assert.equal(updated.name, "Updated");
  assert.equal(updated.visibility, "SENSITIVE");
  assert.equal(updated.status, "PAUSED");
  assert.equal(updated.accesses.length, 1);
  assert.equal(updated.accesses[0]?.accessLevel, "OWNER");

  await expectProjectMutationRejected(
    updateCoreProjectRecord(member, project.id, validFields("Denied", "denied-project"))
  );
  await expectProjectMutationRejected(
    updateCoreProjectRecord(owner, "x".repeat(129), validFields("Denied", "denied-id"))
  );
  await expectProjectMutationRejected(
    updateCoreProjectRecord(owner, "missing-project", validFields("Denied", "missing-id"))
  );
  await expectProjectMutationRejected(
    updateCoreProjectRecord(owner, project.id, {
      ...validFields("Denied", "invalid-update"),
      status: "ARCHIVED"
    })
  );

  await prisma.project.update({
    where: { id: project.id },
    data: { status: "ARCHIVED" }
  });
  await expectProjectMutationRejected(
    updateCoreProjectRecord(owner, project.id, validFields("Denied", "archived-edit"))
  );

  const audit = await prisma.auditLog.findFirstOrThrow({
    where: { eventType: "CORE_PROJECT_UPDATED" }
  });
  assertSafeProjectAudit(audit.metadata, [
    "private updated description",
    "updated-project",
    "admin@example.invalid",
    project.id
  ]);
});

test("archive is authorized, retains project/access history, and rejects repeats safely", async () => {
  const project = await createCoreProjectRecord(
    owner,
    validFields("Archive", "archive-project")
  );
  await prisma.auditLog.deleteMany();

  await expectProjectMutationRejected(archiveCoreProjectRecord(member, project.id, true));
  await expectProjectMutationRejected(archiveCoreProjectRecord(admin, project.id, false));
  await archiveCoreProjectRecord(admin, project.id, true);
  await expectProjectMutationRejected(archiveCoreProjectRecord(owner, project.id, true));

  const archived = await prisma.project.findUniqueOrThrow({
    where: { id: project.id },
    include: { accesses: true }
  });
  assert.equal(archived.status, "ARCHIVED");
  assert.equal(archived.accesses.length, 1);
  assert.equal(await prisma.project.count({ where: { id: project.id } }), 1);

  const audit = await prisma.auditLog.findFirstOrThrow({
    where: { eventType: "CORE_PROJECT_ARCHIVED" }
  });
  assertSafeProjectAudit(audit.metadata, ["archive-project", "admin@example.invalid", project.id]);
});

function validFields(
  name: string,
  slug: string,
  description = "",
  visibility = "INTERNAL",
  status = "ACTIVE"
): CoreProjectFields {
  return { name, slug, description, visibility, status };
}

function createUser(email: string, role: "OWNER" | "ADMIN" | "MEMBER") {
  return prisma.user.create({
    data: { email, role, isActive: true },
    select: { id: true, role: true }
  });
}

async function expectProjectMutationRejected(operation: Promise<unknown>): Promise<void> {
  await assert.rejects(operation, (error) => {
    assert.equal(error instanceof CoreProjectMutationError, true);
    assert.equal((error as Error).message, "Core project mutation rejected.");
    return true;
  });
}

function assertSafeProjectAudit(metadata: unknown, forbiddenValues: string[]): void {
  const serialized = JSON.stringify(metadata);

  for (const value of forbiddenValues) {
    assert.equal(serialized.includes(value), false);
  }

  const keys = Object.keys((metadata ?? {}) as Record<string, unknown>).sort();
  assert.equal(keys.includes("projectRef"), true);
  assert.equal(keys.includes("status"), true);
  assert.equal(keys.every((key) => ["projectRef", "status", "visibility"].includes(key)), true);
}
