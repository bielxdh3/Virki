import assert from "node:assert/strict";
import test from "node:test";
import { isExactRedirectUriAllowed, validateProjectConnectionInput, validateProjectLaunchUrl } from "./connection-policy";

test("connection input accepts canonical origins and exact HTTPS redirect URIs", () => {
  assert.deepEqual(validateProjectConnectionInput({
    name: "Project Alpha",
    slug: "project-alpha",
    origin: "https://project.example.invalid",
    launchUrl: "",
    redirectUris: "https://project.example.invalid/auth/callback"
  }), {
    name: "Project Alpha",
    slug: "project-alpha",
    origin: "https://project.example.invalid",
    launchUrl: null,
    redirectUris: ["https://project.example.invalid/auth/callback"]
  });
});

test("connection launch URL remains on its canonical HTTPS origin", () => {
  assert.equal(validateProjectLaunchUrl("https://project.example.invalid", "https://project.example.invalid/start"), "https://project.example.invalid/start");
  for (const value of ["http://project.example.invalid/start", "https://other.example.invalid/start", "https://user:secret@project.example.invalid/start", "https://project.example.invalid/start?next=/admin", "https://project.example.invalid/start#fragment"]) {
    assert.throws(() => validateProjectLaunchUrl("https://project.example.invalid", value));
  }
});

test("redirect URI matching is exact and does not accept wildcard or origin-only matches", () => {
  const allowlist = ["https://project.example.invalid/auth/callback"];
  assert.equal(isExactRedirectUriAllowed(allowlist, "https://project.example.invalid/auth/callback"), true);
  assert.equal(isExactRedirectUriAllowed(allowlist, "https://project.example.invalid/other"), false);
  assert.throws(() => validateProjectConnectionInput({ name: "Alpha", slug: "alpha", origin: "https://project.example.invalid", redirectUris: "https://project.example.invalid/*" }));
});

test("connection validation rejects HTTP, credentials, fragments, and noncanonical URLs", () => {
  for (const redirectUri of [
    "http://project.example.invalid/callback",
    "https://user:password@project.example.invalid/callback",
    "https://project.example.invalid/callback#fragment",
    "https://project.example.invalid:443/callback"
  ]) {
    assert.throws(() => validateProjectConnectionInput({ name: "Alpha", slug: "alpha", origin: "https://project.example.invalid", redirectUris: redirectUri }));
  }
});
