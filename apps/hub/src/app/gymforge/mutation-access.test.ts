import assert from "node:assert/strict";
import test from "node:test";

import { requireGymForgeMutationAccess } from "./mutation-access";

test("rejects missing or invalid required Access assertions before a GymForge mutation can continue", async () => {
  for (const status of ["missing", "invalid"] as const) {
    const steps: string[] = [];

    await assert.rejects(
      () => requireGymForgeMutationAccess(new Headers(), "gymforge-test", {
        validateAccess: async () => {
          steps.push("access-validation");
          return {
            allowed: false,
            required: true,
            status,
            reason: status === "missing" ? "missing-cloudflare-access-jwt" : "invalid-cloudflare-access-jwt"
          };
        },
        isAccessAllowed: (result) => {
          steps.push("access-decision");
          return result.allowed;
        },
        deny: () => {
          steps.push("denied");
          throw new Error("forbidden");
        }
      }),
      /forbidden/
    );

    assert.deepEqual(steps, ["access-validation", "access-decision", "denied"]);
  }
});

test("allows the validated Access result to continue to the existing GymForge guard", async () => {
  let denied = false;

  await requireGymForgeMutationAccess(new Headers(), "gymforge-test", {
    validateAccess: async () => ({ allowed: true, required: true, status: "valid" }),
    isAccessAllowed: (result) => result.allowed,
    deny: () => {
      denied = true;
      throw new Error("forbidden");
    }
  });

  assert.equal(denied, false);
});
