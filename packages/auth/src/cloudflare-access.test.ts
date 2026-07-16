import assert from "node:assert/strict";
import test from "node:test";
import { classifyCloudflareAccessJwtError } from "./cloudflare-access";

test("classifies supported Cloudflare Access JWT failures", () => {
  assert.equal(
    classifyCloudflareAccessJwtError({ code: "ERR_JWT_EXPIRED" }),
    "expired-cloudflare-access-jwt"
  );
  assert.equal(
    classifyCloudflareAccessJwtError({ code: "ERR_JWT_CLAIM_VALIDATION_FAILED", claim: "aud" }),
    "invalid-cloudflare-access-audience"
  );
  assert.equal(
    classifyCloudflareAccessJwtError({ code: "ERR_JWT_CLAIM_VALIDATION_FAILED", claim: "iss" }),
    "invalid-cloudflare-access-issuer"
  );
  assert.equal(
    classifyCloudflareAccessJwtError({ code: "ERR_JWT_CLAIM_VALIDATION_FAILED", claim: "nbf" }),
    "inactive-cloudflare-access-jwt"
  );
  assert.equal(
    classifyCloudflareAccessJwtError({ code: "ERR_JWS_SIGNATURE_VERIFICATION_FAILED" }),
    "invalid-cloudflare-access-signature"
  );
  assert.equal(
    classifyCloudflareAccessJwtError({ code: "ERR_JWKS_NO_MATCHING_KEY" }),
    "missing-cloudflare-access-signing-key"
  );
});

test("maps unsupported or malformed failures to the generic category", () => {
  assert.equal(
    classifyCloudflareAccessJwtError({ code: "ERR_PRIVATE_UNKNOWN" }),
    "invalid-cloudflare-access-jwt"
  );
  assert.equal(
    classifyCloudflareAccessJwtError({ code: "ERR_JWT_CLAIM_VALIDATION_FAILED", claim: "private" }),
    "invalid-cloudflare-access-jwt"
  );
  assert.equal(classifyCloudflareAccessJwtError(new Error("private detail")), "invalid-cloudflare-access-jwt");
  assert.equal(classifyCloudflareAccessJwtError("private detail"), "invalid-cloudflare-access-jwt");
  assert.equal(classifyCloudflareAccessJwtError({ code: 401 }), "invalid-cloudflare-access-jwt");
});

test("never returns raw JOSE or private failure details", () => {
  const privateValues = [
    "private detail",
    "ERR_PRIVATE_UNKNOWN",
    "private-claim",
    "expected-audience",
    "actual-audience",
    "https://team.example.invalid",
    "synthetic-token-data"
  ];

  for (const privateValue of privateValues) {
    const category = classifyCloudflareAccessJwtError({
      code: "ERR_PRIVATE_UNKNOWN",
      claim: "private-claim",
      message: privateValue,
      payload: privateValue
    });

    assert.equal(category, "invalid-cloudflare-access-jwt");
    assert.equal(category.includes(privateValue), false);
  }
});
