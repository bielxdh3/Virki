import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import test from "node:test";
import { AdminSecurityPanel, getFeedbackForStage } from "./admin-panel";
import { getInitialElevationScope } from "./admin/elevation-scope";

test("administrative security UI exposes only implemented scopes and safe password controls", () => {
  const markup = renderToStaticMarkup(createElement(AdminSecurityPanel, {
    csrfToken: "csrf-token",
    credentialConfigured: true,
    activeElevations: []
  }));

  assert.match(markup, /value="PROJECT_OWNER_ACCESS_CHANGE"/);
  assert.match(markup, /value="CORE_PROJECT_ARCHIVE"/);
  assert.match(markup, /id="admin-elevation-form"/);
  assert.match(markup, /<option value="ACCOUNT_APPLICATION_REVIEW" selected="">/);
  assert.doesNotMatch(markup, /value="GLOBAL_ROLE_CHANGE"/);
  assert.doesNotMatch(markup, /value="MODULE_CATALOG_CHANGE"/);
  assert.match(markup, /aria-label="Show Normal password"/);
  assert.match(markup, /aria-label="Show Administrative password"/);
  assert.match(markup, /name="minutes"/);
  assert.match(markup, /Manual until revoked/);

  const projectAccessMarkup = renderToStaticMarkup(createElement(AdminSecurityPanel, {
    csrfToken: "csrf-token",
    credentialConfigured: true,
    activeElevations: [],
    initialElevationScope: "PROJECT_OWNER_ACCESS_CHANGE"
  }));
  assert.match(projectAccessMarkup, /<option value="PROJECT_OWNER_ACCESS_CHANGE" selected="">/);
});

test("administrative feedback follows the submitted stage", () => {
  const feedback = getFeedbackForStage("elevation", {
    setup: { status: "idle" },
    "setup-complete": { status: "idle" },
    elevation: { status: "error" },
    "elevation-complete": { status: "ok" },
    recovery: { status: "idle" }
  });

  assert.equal(feedback?.stage, "elevation");
  assert.equal(feedback?.state.status, "error");
});

test("project links select only allowlisted elevation scopes", () => {
  assert.equal(getInitialElevationScope("PROJECT_OWNER_ACCESS_CHANGE"), "PROJECT_OWNER_ACCESS_CHANGE");
  assert.equal(getInitialElevationScope("project-access"), "PROJECT_OWNER_ACCESS_CHANGE");
  assert.equal(getInitialElevationScope("project-archive"), "CORE_PROJECT_ARCHIVE");
  assert.equal(getInitialElevationScope("GLOBAL_ROLE_CHANGE"), "ACCOUNT_APPLICATION_REVIEW");
  assert.equal(getInitialElevationScope(undefined), "ACCOUNT_APPLICATION_REVIEW");
});
