import assert from "node:assert/strict";
import test from "node:test";

import {
  getSafeAuthCommandFailureMessage,
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
