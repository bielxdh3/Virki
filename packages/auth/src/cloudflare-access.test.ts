import assert from "node:assert/strict";
import test from "node:test";
import { classifyCloudflareAccessJwtError } from "./cloudflare-access";

test("classifies Cloudflare Access JWT failures without exposing error details", () => {
  assert.equal(
    classifyCloudflareAccessJwtError({ code: "ERR_JWT_CLAIM_VALIDATION_FAILED", claim: "aud" }),
    "invalid-cloudflare-access-audience"
  );
  assert.equal(
    classifyCloudflareAccessJwtError({ code: "ERR_JWT_CLAIM_VALIDATION_FAILED", claim: "iss" }),
    "invalid-cloudflare-access-issuer"
  );
  assert.equal(
    classifyCloudflareAccessJwtError({ code: "ERR_JWS_SIGNATURE_VERIFICATION_FAILED" }),
    "invalid-cloudflare-access-signature"
  );
  assert.equal(
    classifyCloudflareAccessJwtError({ code: "ERR_JWKS_NO_MATCHING_KEY" }),
    "missing-cloudflare-access-signing-key"
  );
  assert.equal(classifyCloudflareAccessJwtError(new Error("private detail")), "invalid-cloudflare-access-jwt");
});
