import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import test from "node:test";
import { AdminSecurityPanel, getFeedbackForStage } from "./admin-panel";

test("administrative security UI exposes only implemented scopes and safe password controls", () => {
  const markup = renderToStaticMarkup(createElement(AdminSecurityPanel, {
    csrfToken: "csrf-token",
    credentialConfigured: true,
    activeElevations: []
  }));

  assert.match(markup, /value="PROJECT_OWNER_ACCESS_CHANGE"/);
  assert.match(markup, /value="CORE_PROJECT_ARCHIVE"/);
  assert.doesNotMatch(markup, /value="GLOBAL_ROLE_CHANGE"/);
  assert.doesNotMatch(markup, /value="MODULE_CATALOG_CHANGE"/);
  assert.match(markup, /aria-label="Show Normal password"/);
  assert.match(markup, /aria-label="Show Administrative password"/);
  assert.match(markup, /name="minutes"/);
  assert.match(markup, /Manual until revoked/);
});

test("administrative feedback follows the submitted stage", () => {
  const feedback = getFeedbackForStage("elevation", {
    setup: { status: "idle" },
    "setup-complete": { status: "idle" },
    elevation: { status: "error" },
    "elevation-complete": { status: "ok" }
  });

  assert.equal(feedback?.stage, "elevation");
  assert.equal(feedback?.state.status, "error");
});
