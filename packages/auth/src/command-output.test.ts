import assert from "node:assert/strict";
import test from "node:test";

import {
  getSafeAuthCommandFailureMessage,
  runAuthCommand,
  type AuthCommandName
} from "./command-output";

const expectedMessages: Record<AuthCommandName, string> = {
  "audit-cleanup": "Audit log cleanup failed.",
  "audit-recent": "Recent audit log inspection failed.",
  "owner-seed": "OWNER seed failed.",
  "session-cleanup": "Inactive session cleanup failed."
};

test("operational auth commands use fixed failure messages", () => {
  for (const [command, expected] of Object.entries(expectedMessages)) {
    const message = getSafeAuthCommandFailureMessage(command as AuthCommandName);
    assert.equal(message, expected);
    assert.equal(message.includes("postgresql://"), false);
    assert.equal(message.includes("Prisma"), false);
  }
});

test("operational command boundaries discard runtime errors and always disconnect", async () => {
  const privateRuntimeDetail = "private-runtime-detail";

  for (const [command, expected] of Object.entries(expectedMessages)) {
    const output: string[] = [];
    const exitCodes: number[] = [];
    let disconnected = false;

    await runAuthCommand(
      command as AuthCommandName,
      async () => {
        throw new Error(`ORM failure: ${privateRuntimeDetail}`);
      },
      async () => {
        disconnected = true;
      },
      (message) => output.push(message),
      (code) => exitCodes.push(code)
    );

    assert.equal(disconnected, true);
    assert.deepEqual(output, [expected]);
    assert.deepEqual(exitCodes, [1]);
    assert.equal(output.join(" ").includes(privateRuntimeDetail), false);
    assert.equal(output.join(" ").includes("ORM failure"), false);
  }
});

test("disconnect failures also use the fixed command boundary", async () => {
  const output: string[] = [];
  const exitCodes: number[] = [];

  await runAuthCommand(
    "session-cleanup",
    async () => undefined,
    async () => {
      throw new Error("private-disconnect-detail");
    },
    (message) => output.push(message),
    (code) => exitCodes.push(code)
  );

  assert.deepEqual(output, ["Inactive session cleanup failed."]);
  assert.deepEqual(exitCodes, [1]);
  assert.equal(output.join(" ").includes("private-disconnect-detail"), false);
});
