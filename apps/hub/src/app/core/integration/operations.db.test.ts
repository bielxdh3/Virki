import assert from "node:assert/strict";
import { after, test } from "node:test";

import { getCoreOperationsSnapshot } from "../operations";
import {
  assertCoreIntegrationTestDatabase,
  disconnectCoreIntegrationTestDatabase
} from "./test-database";

after(async () => {
  await disconnectCoreIntegrationTestDatabase();
});

test("operations snapshot verifies a bounded query on disposable PostgreSQL", async () => {
  await assertCoreIntegrationTestDatabase();

  const snapshot = await getCoreOperationsSnapshot();

  assert.deepEqual(snapshot, {
    hubRequest: "verified",
    authenticatedSession: "verified",
    database: "verified",
    emailTransport: "configured",
    intake: "disabled",
    emailWorker: "not-checked"
  });
});
