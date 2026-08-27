import assert from "node:assert/strict";
import test from "node:test";

import {
  getCoreProjectActionFeedback,
  getCoreProjectFeedbackMessage
} from "./feedback";

test("project action errors take precedence over success query values", () => {
  const feedback = getCoreProjectActionFeedback({
    status: "access-granted",
    error: "project-access"
  });

  assert.deepEqual(feedback, { kind: "error", code: "project-access" });
  assert.equal(
    getCoreProjectFeedbackMessage(feedback!, {
      actionError: "fallback",
      feedbackProjectAccess: "Access was rejected."
    }),
    "Access was rejected."
  );
});

test("project action feedback allowlists successful access outcomes", () => {
  assert.deepEqual(
    getCoreProjectActionFeedback({ status: "access-granted" }),
    { kind: "success", code: "access-granted" }
  );
  assert.deepEqual(
    getCoreProjectActionFeedback({ status: "access-unchanged" }),
    { kind: "success", code: "access-unchanged" }
  );
  assert.equal(getCoreProjectActionFeedback({ status: "access-failed" }), null);
  assert.equal(getCoreProjectActionFeedback({ error: ["project-access"] }), null);
});
