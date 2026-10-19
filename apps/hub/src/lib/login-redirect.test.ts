import assert from "node:assert/strict";
import test from "node:test";
import { getLoginRedirectPath } from "./login-redirect";

test("recovery notice takes priority while preserving a validated OIDC return target", () => {
  assert.equal(
    getLoginRedirectPath("/interaction/abcdefgh?marker=opaque", "/account/security?recovered=totp", "/"),
    "/account/security?recovered=totp&returnTo=%2Finteraction%2Fabcdefgh%3Fmarker%3Dopaque"
  );
});

test("ordinary login retains its return target and uses the surface default when absent", () => {
  assert.equal(getLoginRedirectPath("/account/security", undefined, "/"), "/account/security");
  assert.equal(getLoginRedirectPath(null, undefined, "/"), "/");
});
