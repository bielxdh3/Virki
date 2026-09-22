import assert from "node:assert/strict";
import test from "node:test";
import { isExactRedirectUriAllowed, validateProjectConnectionInput } from "./connection-policy";

test("connection input accepts canonical origins and exact HTTPS redirect URIs", () => {
  assert.deepEqual(validateProjectConnectionInput({
    name: "Project Alpha",
    slug: "project-alpha",
    origin: "https://project.example.invalid",
    redirectUris: "https://project.example.invalid/auth/callback"
  }), {
    name: "Project Alpha",
    slug: "project-alpha",
    origin: "https://project.example.invalid",
    redirectUris: ["https://project.example.invalid/auth/callback"]
  });
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
