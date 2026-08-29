import assert from "node:assert/strict";
import { mock, after, before, beforeEach, test } from "node:test";

import { hashSessionToken } from "@bielos/auth";
import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import { prisma } from "@bielos/database";

import { findCoreProjectDetailForPrincipal } from "../projects/read-service";
import {
  cleanCoreIntegrationTestData,
  disconnectCoreIntegrationTestDatabase
} from "./test-database";
import { actionRuntime } from "../projects/action-runtime";

class Redirected extends Error {
  constructor(readonly location: string) {
    super("redirected");
  }
}

let session: { id: string; user: { id: string; role: string } } | null = null;
const revalidatedPaths: string[] = [];

mock.method(actionRuntime, "getRequestHeaders", async () => new Headers());
mock.method(actionRuntime, "deny", () => { throw new Error("forbidden"); });
mock.method(actionRuntime, "go", (location: string) => { throw new Redirected(location); });
mock.method(actionRuntime, "revalidate", (path: string) => { revalidatedPaths.push(path); });
mock.method(actionRuntime, "getSession", async () => session);
mock.method(actionRuntime, "accessAllowed", () => true);
mock.method(actionRuntime, "validateAccess", async () => ({ allowed: true }));

let setCoreProjectAccess: typeof import("../projects/actions").setCoreProjectAccess;

before(async () => {
  ({ setCoreProjectAccess } = await import("../projects/actions"));
});

beforeEach(async () => {
  await cleanCoreIntegrationTestData();
  session = null;
  revalidatedPaths.length = 0;
});

after(async () => {
  await cleanCoreIntegrationTestData();
  await disconnectCoreIntegrationTestDatabase();
});

test("the server action consumes the browser form, persists access, and redirects after read-back revalidation", async () => {
  const owner = await createUser("wrapper-owner@example.invalid", "OWNER");
  const member = await createUser("wrapper-member@example.invalid", "MEMBER");
  const project = await prisma.project.create({
    data: {
      name: "wrapper-project",
      slug: "wrapper-project",
      status: "ACTIVE",
      visibility: "INTERNAL",
      accesses: { create: { userId: owner.id, accessLevel: "OWNER" } }
    },
    select: { id: true }
  });
  const dbSession = await prisma.session.create({
    data: {
      userId: owner.id,
      tokenHash: hashSessionToken("wrapper-session-token"),
      expiresAt: new Date(Date.now() + 60_000)
    },
    select: { id: true }
  });
  await prisma.securityElevation.create({
    data: {
      requestKey: "wrapper-elevation-request-key-1234567890123456",
      userId: owner.id,
      sessionId: dbSession.id,
      protocolVersion: 1,
      scope: "PROJECT_OWNER_ACCESS_CHANGE",
      challengeHash: "wrapper-challenge-hash",
      status: "ACTIVE",
      expiresAt: new Date(Date.now() + 60_000)
    }
  });
  session = { id: dbSession.id, user: owner };

  const formData = new FormData();
  formData.set(CSRF_FORM_FIELD_NAME, createCsrfToken());
  formData.set("projectId", project.id);
  formData.set("userId", member.id);
  formData.set("accessLevel", "OWNER");
  formData.set("returnTo", "detail");

  await assert.rejects(
    setCoreProjectAccess(formData),
    (error) => error instanceof Redirected && error.location.endsWith("?status=access-granted")
  );

  assert.deepEqual(revalidatedPaths, ["/core/projects", `/core/projects/${project.id}`, "/"]);
  assert.equal(
    (await prisma.projectAccess.findUniqueOrThrow({
      where: { userId_projectId: { userId: member.id, projectId: project.id } },
      select: { accessLevel: true }
    })).accessLevel,
    "OWNER"
  );
  assert.equal(
    (await findCoreProjectDetailForPrincipal(owner, project.id))?.accesses.find(
      (access) => access.user.id === member.id
    )?.accessLevel,
    "OWNER"
  );
});

function createUser(email: string, role: "OWNER" | "MEMBER") {
  return prisma.user.create({
    data: { email, role },
    select: { id: true, role: true }
  });
}
