import assert from "node:assert/strict";
import { after, beforeEach, test } from "node:test";

import { prisma } from "@bielos/database";

import {
  CORE_AUDIT_DISPLAY_LIMIT,
  listCoreAuditActivity
} from "../security/audit-service";
import {
  cleanCoreIntegrationTestData,
  disconnectCoreIntegrationTestDatabase
} from "./test-database";

const PRIVATE_SENTINEL = "synthetic-private-audit-sentinel";

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

test("only an active persisted OWNER can read audit activity", async () => {
  await createAuditRow({ actorUserId: owner.id });

  assert.equal((await listCoreAuditActivity(owner)).length, 1);
  assert.deepEqual(await listCoreAuditActivity(admin), []);
  assert.deepEqual(await listCoreAuditActivity(member), []);
  assert.deepEqual(
    await listCoreAuditActivity({ id: admin.id, role: "OWNER" }),
    []
  );
  assert.deepEqual(
    await listCoreAuditActivity({ id: owner.id, role: "ADMIN" }),
    []
  );
  assert.deepEqual(
    await listCoreAuditActivity({ id: "missing-owner", role: "OWNER" }),
    []
  );

  await prisma.user.update({ where: { id: owner.id }, data: { isActive: false } });
  assert.deepEqual(await listCoreAuditActivity(owner), []);
});

test("audit display is newest-first, bounded, and excludes private columns", async () => {
  const baseTime = new Date();
  await prisma.auditLog.createMany({
    data: Array.from({ length: CORE_AUDIT_DISPLAY_LIMIT + 10 }, (_, index) => ({
      eventType: "CORE_PROJECT_UPDATED",
      actorUserId: owner.id,
      actorEmailHash: `${PRIVATE_SENTINEL}-hash-${index}`,
      result: "SUCCESS",
      resource: "core.project",
      message: `${PRIVATE_SENTINEL}-message-${index}`,
      metadata: { privateValue: `${PRIVATE_SENTINEL}-metadata-${index}` },
      createdAt: new Date(baseTime.getTime() - index * 1_000)
    }))
  });
  await createAuditRow({
    eventType: "untrusted legacy event",
    result: "untrusted result",
    resource: "private/resource/value",
    actorUserId: owner.id,
    metadata: PRIVATE_SENTINEL,
    createdAt: new Date(baseTime.getTime() + 1_000)
  });
  await createAuditRow({
    eventType: "AUTH_SESSION_CLEANUP",
    result: "INFO",
    resource: null,
    actorUserId: null,
    createdAt: new Date(baseTime.getTime() + 2_000)
  });

  const activity = await listCoreAuditActivity(owner);

  assert.equal(activity.length, CORE_AUDIT_DISPLAY_LIMIT);
  assert.equal(activity[0]?.eventType, "AUTH_SESSION_CLEANUP");
  assert.equal(activity[0]?.actorState, "system");
  assert.equal(activity[0]?.resource, "system");
  assert.deepEqual(activity[1], {
    eventType: "OTHER_EVENT",
    result: "OTHER",
    resource: "other",
    actorState: "user",
    createdAt: new Date(baseTime.getTime() + 1_000)
  });

  for (let index = 1; index < activity.length; index += 1) {
    assert.equal(
      activity[index - 1]!.createdAt.getTime() >= activity[index]!.createdAt.getTime(),
      true
    );
  }

  for (const item of activity) {
    assert.deepEqual(Object.keys(item).sort(), [
      "actorState",
      "createdAt",
      "eventType",
      "resource",
      "result"
    ]);
  }

  const serialized = JSON.stringify(activity);
  assert.equal(serialized.includes(PRIVATE_SENTINEL), false);
  assert.equal(serialized.includes(owner.id), false);
  assert.equal(serialized.includes("owner@example.invalid"), false);
  assert.equal(serialized.includes("metadata"), false);
  assert.equal(serialized.includes("message"), false);
  assert.equal(serialized.includes("actorEmailHash"), false);
  assert.equal(serialized.includes("actorUserId"), false);
});

test("default activity omits access success noise while OWNER infrastructure filter exposes only access events", async () => {
  const baseTime = new Date();
  await prisma.auditLog.createMany({
    data: [
      {
        eventType: "ACCESS_JWT_VALID",
        actorUserId: owner.id,
        result: "SUCCESS",
        resource: "hub",
        createdAt: new Date(baseTime.getTime() + 3_000)
      },
      {
        eventType: "ACCESS_JWT_INVALID",
        actorUserId: null,
        result: "FAILURE",
        resource: "hub",
        createdAt: new Date(baseTime.getTime() + 2_000)
      },
      {
        eventType: "CORE_PROJECT_CREATED",
        actorUserId: owner.id,
        result: "SUCCESS",
        resource: "core.project",
        createdAt: new Date(baseTime.getTime() + 1_000)
      }
    ]
  });

  const activity = await listCoreAuditActivity(owner);
  assert.deepEqual(activity.map((item) => item.eventType), [
    "ACCESS_JWT_INVALID",
    "CORE_PROJECT_CREATED"
  ]);

  const infrastructure = await listCoreAuditActivity(owner, "infrastructure");
  assert.deepEqual(infrastructure.map((item) => item.eventType), [
    "ACCESS_JWT_VALID",
    "ACCESS_JWT_INVALID"
  ]);
  assert.deepEqual(await listCoreAuditActivity(owner, "untrusted-filter"), [
    ...activity
  ]);
});

function createUser(email: string, role: "OWNER" | "ADMIN" | "MEMBER") {
  return prisma.user.create({
    data: { email, role, isActive: true },
    select: { id: true, role: true }
  });
}

function createAuditRow(input: {
  eventType?: string;
  result?: string;
  resource?: string | null;
  actorUserId?: string | null;
  metadata?: string;
  createdAt?: Date;
}) {
  return prisma.auditLog.create({
    data: {
      eventType: input.eventType ?? "CORE_PROJECT_CREATED",
      result: input.result ?? "SUCCESS",
      resource: input.resource === undefined ? "core.project" : input.resource,
      actorUserId: input.actorUserId,
      actorEmailHash: `${PRIVATE_SENTINEL}-hash`,
      message: `${PRIVATE_SENTINEL}-message`,
      metadata: input.metadata ?? { privateValue: PRIVATE_SENTINEL },
      createdAt: input.createdAt
    }
  });
}
