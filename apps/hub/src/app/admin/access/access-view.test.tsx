import assert from "node:assert/strict";
import React from "react";
import test from "node:test";
import { prisma } from "@virki/database";
import { AccessView } from "./access-view";

function collectText(node: unknown): string {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(collectText).join(" ");
  if (!node || typeof node !== "object" || !("props" in node)) return "";
  return collectText((node as { props: { children?: unknown } }).props.children);
}

test("access picker filters active USER accounts and legacy ADMIN grants stay classified and revocable", async () => {
  const testGlobals = globalThis as typeof globalThis & { React?: typeof React };
  const previousReact = testGlobals.React;
  testGlobals.React = React;

  let userQuery: { where?: unknown } | undefined;
  const originalUserFindMany = prisma.user.findMany;
  const originalConnectionFindMany = prisma.projectConnection.findMany;
  const originalGrantFindMany = prisma.userProjectGrant.findMany;
  prisma.user.findMany = (async (query: Parameters<typeof prisma.user.findMany>[0]) => {
    userQuery = query;
    return [{ id: "user-1", email: "user@example.test", displayName: "User" }];
  }) as unknown as typeof originalUserFindMany;
  prisma.projectConnection.findMany = (async () => [
    { id: "connection-1", name: "Project", origin: "https://project.example.test" }
  ]) as unknown as typeof originalConnectionFindMany;
  prisma.userProjectGrant.findMany = (async () => [
    {
      id: "legacy-admin-grant",
      createdAt: new Date("2026-01-01T00:00:00.000Z"),
      user: { email: "admin@example.test", displayName: "Admin", role: "ADMIN" },
      connection: { name: "Project", enabled: true }
    }
  ]) as unknown as typeof originalGrantFindMany;

  try {
    const page = await AccessView({ searchParams: Promise.resolve({}), csrf: "test-csrf-value" });
    assert.deepEqual(userQuery?.where, { role: "USER", isActive: true, accountStatus: "ACTIVE" });

    const renderedText = collectText(page);
    assert.match(renderedText, /Conta ADMIN · concessão legada; não autoriza entrada no projeto\./u);
    assert.match(renderedText, /Revogar/u, "the legacy row still offers the existing revoke action");
  } finally {
    prisma.user.findMany = originalUserFindMany;
    prisma.projectConnection.findMany = originalConnectionFindMany;
    prisma.userProjectGrant.findMany = originalGrantFindMany;
    if (previousReact) testGlobals.React = previousReact;
    else Reflect.deleteProperty(testGlobals, "React");
  }
});
