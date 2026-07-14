import assert from "node:assert/strict";
import { after, beforeEach, test } from "node:test";

import { prisma } from "@bielos/database";

import {
  CoreProjectAccessMutationError,
  revokeCoreProjectAccessRecord,
  setCoreProjectAccessRecord
} from "../projects/access-service";
import {
  archiveCoreProjectRecord,
  CoreProjectMutationError,
  createCoreProjectRecord
} from "../projects/mutation-service";
import {
  cleanCoreIntegrationTestData,
  disconnectCoreIntegrationTestDatabase
} from "./test-database";

let owner: { id: string; role: string };
let admin: { id: string; role: string };
let firstMember: { id: string; role: string };

beforeEach(async () => {
  await cleanCoreIntegrationTestData();
  [owner, admin, firstMember] = await Promise.all([
    createUser("owner@example.invalid", "OWNER"),
    createUser("admin@example.invalid", "ADMIN"),
    createUser("member-a@example.invalid", "MEMBER")
  ]);
});

after(async () => {
  await cleanCoreIntegrationTestData();
  await disconnectCoreIntegrationTestDatabase();
});

test("simultaneous grants converge on one access row", async () => {
  const project = await createProject("grant-race", owner.id);

  const results = await Promise.allSettled([
    setCoreProjectAccessRecord(owner, project.id, firstMember.id, "VIEWER"),
    setCoreProjectAccessRecord(owner, project.id, firstMember.id, "VIEWER")
  ]);

  assert.equal(results.every((result) => result.status === "fulfilled"), true);
  const resultKinds = results.map((result) =>
    result.status === "fulfilled" ? result.value.kind : "rejected"
  );
  assert.deepEqual(resultKinds.sort(), ["granted", "unchanged"]);
  assert.equal(
    await prisma.projectAccess.count({
      where: { projectId: project.id, userId: firstMember.id }
    }),
    1
  );
});

test("simultaneous access changes leave one valid level and one row", async () => {
  const project = await createProject("change-race", owner.id);
  await setCoreProjectAccessRecord(owner, project.id, firstMember.id, "VIEWER");

  const results = await Promise.allSettled([
    setCoreProjectAccessRecord(owner, project.id, firstMember.id, "EDITOR"),
    setCoreProjectAccessRecord(owner, project.id, firstMember.id, "OWNER")
  ]);

  assert.equal(results.every((result) => result.status === "fulfilled"), true);
  const accesses = await prisma.projectAccess.findMany({
    where: { projectId: project.id, userId: firstMember.id }
  });
  assert.equal(accesses.length, 1);
  assert.equal(["EDITOR", "OWNER"].includes(accesses[0]?.accessLevel ?? ""), true);
});

test("simultaneous owner revocations cannot remove the final active owner", async () => {
  const project = await createProject("revoke-race", owner.id);
  await setCoreProjectAccessRecord(owner, project.id, firstMember.id, "OWNER");

  const results = await Promise.allSettled([
    revokeCoreProjectAccessRecord(owner, project.id, owner.id),
    revokeCoreProjectAccessRecord(owner, project.id, firstMember.id)
  ]);

  assertOneAccessOperationRejected(results);
  assert.equal(await countActiveOwners(project.id), 1);
});

test("simultaneous owner downgrade and revoke cannot produce zero owners", async () => {
  const project = await createProject("mixed-owner-race", owner.id);
  await setCoreProjectAccessRecord(owner, project.id, firstMember.id, "OWNER");

  const results = await Promise.allSettled([
    setCoreProjectAccessRecord(owner, project.id, firstMember.id, "EDITOR"),
    revokeCoreProjectAccessRecord(owner, project.id, owner.id)
  ]);

  assertOneAccessOperationRejected(results);
  assert.equal(await countActiveOwners(project.id), 1);
  assert.equal(
    [1, 2].includes(await prisma.projectAccess.count({ where: { projectId: project.id } })),
    true
  );
});

test("simultaneous archive and access grant serialize without post-archive mutation", async () => {
  const project = await createProject("archive-race", owner.id);

  const [archiveResult, accessResult] = await Promise.allSettled([
    archiveCoreProjectRecord(owner, project.id, true),
    setCoreProjectAccessRecord(owner, project.id, firstMember.id, "VIEWER")
  ]);

  assert.equal(archiveResult.status, "fulfilled");
  assert.equal(
    (await prisma.project.findUniqueOrThrow({ where: { id: project.id } })).status,
    "ARCHIVED"
  );

  const grantedCount = await prisma.projectAccess.count({
    where: { projectId: project.id, userId: firstMember.id }
  });

  if (accessResult.status === "fulfilled") {
    assert.equal(accessResult.value.kind, "granted");
    assert.equal(grantedCount, 1);
  } else {
    assert.equal(accessResult.reason instanceof CoreProjectAccessMutationError, true);
    assert.equal(grantedCount, 0);
  }
});

test("simultaneous duplicate project creation preserves slug uniqueness", async () => {
  const fields = {
    name: "Duplicate Race",
    slug: "duplicate-race",
    description: "",
    visibility: "INTERNAL",
    status: "ACTIVE"
  };

  const results = await Promise.allSettled([
    createCoreProjectRecord(owner, fields),
    createCoreProjectRecord(admin, fields)
  ]);

  assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
  const rejected = results.find(
    (result): result is PromiseRejectedResult => result.status === "rejected"
  );
  assert.equal(rejected?.reason instanceof CoreProjectMutationError, true);
  assert.equal(await prisma.project.count({ where: { slug: fields.slug } }), 1);
  assert.equal(await prisma.projectAccess.count(), 1);
});

function createUser(email: string, role: "OWNER" | "ADMIN" | "MEMBER") {
  return prisma.user.create({
    data: { email, role, isActive: true },
    select: { id: true, role: true }
  });
}

async function createProject(slug: string, ownerUserId: string) {
  return prisma.project.create({
    data: {
      name: slug,
      slug,
      status: "ACTIVE",
      visibility: "INTERNAL",
      accesses: {
        create: { userId: ownerUserId, accessLevel: "OWNER" }
      }
    },
    select: { id: true }
  });
}

function assertOneAccessOperationRejected(
  results: PromiseSettledResult<unknown>[]
): void {
  assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
  const rejected = results.find(
    (result): result is PromiseRejectedResult => result.status === "rejected"
  );
  assert.equal(rejected?.reason instanceof CoreProjectAccessMutationError, true);
}

function countActiveOwners(projectId: string) {
  return prisma.projectAccess.count({
    where: {
      projectId,
      accessLevel: "OWNER",
      user: { isActive: true }
    }
  });
}
