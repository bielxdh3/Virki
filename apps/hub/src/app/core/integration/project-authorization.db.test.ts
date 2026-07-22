import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import { prisma } from "@bielos/database";

import {
  CORE_PROJECT_ACCESS_READ_LIMIT,
  findCoreProjectDetailForPrincipal,
  findCoreProjectForPrincipal,
  listCoreProjectsForPrincipal
} from "../projects/read-service";
import { getCoreProjectDetailPath } from "../projects/detail-policy";
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

    const detail = await findCoreProjectDetailForPrincipal(
      principal,
      data.sensitiveRestricted.id
    );
    assert.ok(detail?.administrator);
    assert.equal(detail.description, "restricted sensitive description");
    assert.equal(
      detail.effectiveAccess,
      principal.role === "OWNER" ? "GLOBAL_OWNER" : "GLOBAL_ADMIN"
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

  for (const project of [
    data.publicActive,
    data.internalGranted,
    data.internalArchived,
    data.sensitiveGranted
  ]) {
    const detail = await findCoreProjectDetailForPrincipal(data.memberA, project.id);
    assert.ok(detail && !detail.administrator);
    assert.equal(detail.id, project.id);
    assert.deepEqual(detail.accesses, []);
    assert.deepEqual(detail.activeUsers, []);
    assert.equal(JSON.stringify(detail).includes("@example.invalid"), false);
  }

  const visibleLinks = projects.map((project) => getCoreProjectDetailPath(project.id));
  assert.equal(visibleLinks.includes(getCoreProjectDetailPath(data.internalRestricted.id)), false);
  assert.equal(visibleLinks.includes(getCoreProjectDetailPath(data.sensitiveRestricted.id)), false);

  const publicDetail = await findCoreProjectDetailForPrincipal(data.memberB, data.publicActive.id);
  assert.equal(publicDetail?.effectiveAccess, "AUTHENTICATED");
  assert.equal(
    (await findCoreProjectDetailForPrincipal(data.memberA, data.internalGranted.id))?.effectiveAccess,
    "VIEWER"
  );
  assert.equal(
    (await findCoreProjectDetailForPrincipal(data.memberA, data.sensitiveGranted.id))?.effectiveAccess,
    "EDITOR"
  );
  assert.equal(
    (await findCoreProjectDetailForPrincipal(data.memberA, data.internalArchived.id))?.status,
    "ARCHIVED"
  );
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
    assert.equal(
      await findCoreProjectDetailForPrincipal(data.memberB, hiddenProject.id),
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
  assert.equal(
    await findCoreProjectDetailForPrincipal(data.memberB, "x".repeat(129)),
    null
  );
  assert.equal(
    await findCoreProjectDetailForPrincipal(data.memberB, "missing-project-id"),
    null
  );
  assert.equal(
    await findCoreProjectDetailForPrincipal(data.inactiveMember, data.publicActive.id),
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
  assert.equal(
    await findCoreProjectDetailForPrincipal(forgedOwner, data.sensitiveRestricted.id),
    null
  );
  assert.equal(
    await findCoreProjectDetailForPrincipal(invalidRole, data.internalRestricted.id),
    null
  );
});

test("administrator project detail access rows are deterministic and bounded", async () => {
  const extraUsers = Array.from({ length: CORE_PROJECT_ACCESS_READ_LIMIT + 5 }, (_, index) => ({
    email: `bounded-${String(index).padStart(3, "0")}@example.invalid`,
    role: "MEMBER" as const,
    isActive: true
  }));
  await prisma.user.createMany({ data: extraUsers });
  const users = await prisma.user.findMany({
    where: { email: { startsWith: "bounded-" } },
    select: { id: true },
    orderBy: { email: "asc" }
  });
  await prisma.projectAccess.createMany({
    data: users.map((user) => ({
      projectId: data.publicActive.id,
      userId: user.id,
      accessLevel: "VIEWER"
    }))
  });

  const detail = await findCoreProjectDetailForPrincipal(data.owner, data.publicActive.id);
  assert.ok(detail?.administrator);
  assert.equal(detail.accesses.length, CORE_PROJECT_ACCESS_READ_LIMIT);
  assert.equal(
    detail.accesses.every((access) => access.user.email.endsWith("@example.invalid")),
    true
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
