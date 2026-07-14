import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import { prisma } from "@bielos/database";

import {
  findCoreProjectForPrincipal,
  listCoreProjectsForPrincipal
} from "../projects/read-service";
import {
  cleanCoreIntegrationTestData,
  disconnectCoreIntegrationTestDatabase
} from "./test-database";

type SeededAuthorizationData = Awaited<ReturnType<typeof seedAuthorizationData>>;

let data: SeededAuthorizationData;

before(async () => {
  await cleanCoreIntegrationTestData();
  data = await seedAuthorizationData();
});

after(async () => {
  await cleanCoreIntegrationTestData();
  await disconnectCoreIntegrationTestDatabase();
});

test("OWNER and ADMIN can read every Core project lifecycle and visibility", async () => {
  for (const principal of [data.owner, data.admin]) {
    const projects = await listCoreProjectsForPrincipal(principal);
    const projectIds = new Set(projects.map((project) => project.id));

    assert.equal(projectIds.size, data.projects.length);

    for (const project of data.projects) {
      assert.equal(projectIds.has(project.id), true);
    }

    assert.equal(projects.some((project) => project.status === "ACTIVE"), true);
    assert.equal(projects.some((project) => project.status === "PAUSED"), true);
    assert.equal(projects.some((project) => project.status === "ARCHIVED"), true);
    assert.equal(projects.some((project) => project.visibility === "PUBLIC"), true);
    assert.equal(projects.some((project) => project.visibility === "INTERNAL"), true);
    assert.equal(projects.some((project) => project.visibility === "SENSITIVE"), true);

    assert.equal(
      await findCoreProjectForPrincipal(principal, "missing-project-id"),
      null
    );
  }
});

test("MEMBER reads public and explicitly granted projects across documented statuses", async () => {
  const projects = await listCoreProjectsForPrincipal(data.memberA);
  const projectIds = new Set(projects.map((project) => project.id));

  assert.equal(projectIds.has(data.publicActive.id), true);
  assert.equal(projectIds.has(data.publicPaused.id), true);
  assert.equal(projectIds.has(data.publicArchived.id), true);
  assert.equal(projectIds.has(data.internalGranted.id), true);
  assert.equal(projectIds.has(data.internalArchived.id), true);
  assert.equal(projectIds.has(data.sensitiveGranted.id), true);
  assert.equal(projectIds.has(data.internalRestricted.id), false);
  assert.equal(projectIds.has(data.sensitiveRestricted.id), false);

  const serialized = JSON.stringify(projects);
  assert.equal(serialized.includes("owner@example.invalid"), false);
  assert.equal(serialized.includes("admin@example.invalid"), false);
  assert.equal(serialized.includes("member-b@example.invalid"), false);
});

test("ungranted and inactive MEMBER principals cannot retrieve restricted data", async () => {
  const memberBProjects = await listCoreProjectsForPrincipal(data.memberB);
  const memberBIds = new Set(memberBProjects.map((project) => project.id));

  assert.equal(memberBIds.has(data.internalGranted.id), false);
  assert.equal(memberBIds.has(data.sensitiveGranted.id), false);
  assert.deepEqual(await listCoreProjectsForPrincipal(data.inactiveMember), []);

  for (const hiddenProject of [data.internalGranted, data.sensitiveGranted]) {
    assert.equal(
      await findCoreProjectForPrincipal(data.memberB, hiddenProject.id),
      null
    );
  }

  assert.equal(
    await findCoreProjectForPrincipal(data.memberB, "x".repeat(129)),
    null
  );
  assert.equal(
    await findCoreProjectForPrincipal(data.memberB, "missing-project-id"),
    null
  );

  const serialized = JSON.stringify(memberBProjects);
  assert.equal(serialized.includes("restricted internal description"), false);
  assert.equal(serialized.includes("restricted-sensitive"), false);
  assert.equal(serialized.includes(data.memberA.id), false);
});

test("crafted or stale principal roles cannot widen project reads", async () => {
  const forgedOwner = { id: data.memberB.id, role: "OWNER" };
  const invalidRole = { id: data.memberB.id, role: "SUPERUSER" };

  assert.deepEqual(await listCoreProjectsForPrincipal(forgedOwner), []);
  assert.deepEqual(await listCoreProjectsForPrincipal(invalidRole), []);
  assert.equal(
    await findCoreProjectForPrincipal(forgedOwner, data.sensitiveRestricted.id),
    null
  );
  assert.equal(
    await findCoreProjectForPrincipal(invalidRole, data.internalRestricted.id),
    null
  );
});

async function seedAuthorizationData() {
  const [owner, admin, memberA, memberB, inactiveMember] = await Promise.all([
    createUser("owner@example.invalid", "OWNER", true),
    createUser("admin@example.invalid", "ADMIN", true),
    createUser("member-a@example.invalid", "MEMBER", true),
    createUser("member-b@example.invalid", "MEMBER", true),
    createUser("inactive-member@example.invalid", "MEMBER", false)
  ]);

  const publicActive = await createProject("public-active", "PUBLIC", "ACTIVE");
  const publicPaused = await createProject("public-paused", "PUBLIC", "PAUSED");
  const publicArchived = await createProject("public-archived", "PUBLIC", "ARCHIVED");
  const internalGranted = await createProject("internal-granted", "INTERNAL", "ACTIVE");
  const internalArchived = await createProject("internal-archived", "INTERNAL", "ARCHIVED");
  const sensitiveGranted = await createProject("sensitive-granted", "SENSITIVE", "PAUSED");
  const internalRestricted = await createProject(
    "restricted-internal",
    "INTERNAL",
    "ACTIVE",
    "restricted internal description"
  );
  const sensitiveRestricted = await createProject(
    "restricted-sensitive",
    "SENSITIVE",
    "ACTIVE",
    "restricted sensitive description"
  );

  await prisma.projectAccess.createMany({
    data: [
      { projectId: internalGranted.id, userId: memberA.id, accessLevel: "VIEWER" },
      { projectId: internalArchived.id, userId: memberA.id, accessLevel: "VIEWER" },
      { projectId: sensitiveGranted.id, userId: memberA.id, accessLevel: "EDITOR" },
      { projectId: internalRestricted.id, userId: inactiveMember.id, accessLevel: "VIEWER" }
    ]
  });

  return {
    owner,
    admin,
    memberA,
    memberB,
    inactiveMember,
    publicActive,
    publicPaused,
    publicArchived,
    internalGranted,
    internalArchived,
    sensitiveGranted,
    internalRestricted,
    sensitiveRestricted,
    projects: [
      publicActive,
      publicPaused,
      publicArchived,
      internalGranted,
      internalArchived,
      sensitiveGranted,
      internalRestricted,
      sensitiveRestricted
    ]
  };
}

function createUser(email: string, role: "OWNER" | "ADMIN" | "MEMBER", isActive: boolean) {
  return prisma.user.create({
    data: { email, role, isActive },
    select: { id: true, role: true }
  });
}

function createProject(
  slug: string,
  visibility: "PUBLIC" | "INTERNAL" | "SENSITIVE",
  status: "ACTIVE" | "PAUSED" | "ARCHIVED",
  description = `${slug} description`
) {
  return prisma.project.create({
    data: {
      name: slug,
      slug,
      description,
      visibility,
      status
    },
    select: { id: true, status: true }
  });
}
