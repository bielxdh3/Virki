import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { ApplyForm } from "./apply-form";
import { ActivateApplication } from "./activate-application";
import { VerifyApplication } from "./verify-application";

test("public application surfaces keep locale copy and accessible reason labels", () => {
  const copy = {
    email: "Email",
    displayName: "Name",
    modules: "Modules",
    reason: "Reason",
    submit: "Submit",
    unavailable: "Unavailable",
    runtimeAvailable: "Available",
    runtimeUnavailable: "Unavailable"
  };
  const form = renderToStaticMarkup(createElement(ApplyForm, {
    locale: "en",
    copy,
    modules: [{ key: "gymforge", name: "GymForge", available: true }],
    apiUrl: ""
  }));
  const verify = renderToStaticMarkup(createElement(VerifyApplication, { endpoint: "", locale: "en" }));
  const activate = renderToStaticMarkup(createElement(ActivateApplication, { endpoint: "", locale: "en" }));

  assert.match(form, /for="reason-gymforge"/);
  assert.match(form, />Reason</);
  assert.match(verify, />Verifying</);
  assert.match(activate, />Activate account</);
  assert.match(activate, />Password</);
});
