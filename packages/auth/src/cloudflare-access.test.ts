import assert from "node:assert/strict";
import test from "node:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import {
  classifyCloudflareAccessJwtError,
  validateCloudflareAccessJwt
} from "./cloudflare-access";

test("validates a signed Access JWT against its issuer, audience, and JWKS", async () => {
  const teamDomain = "https://signed-jwt-test.example.invalid";
  const audience = "signed-jwt-test-audience";
  const keyId = "signed-jwt-test-key";
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwk = await exportJWK(publicKey);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response(JSON.stringify({ keys: [{ ...jwk, kid: keyId, use: "sig", alg: "RS256" }] }), {
    status: 200,
    headers: { "content-type": "application/json" }
  })) as typeof fetch;

  try {
    const token = await new SignJWT({})
      .setProtectedHeader({ alg: "RS256", kid: keyId })
      .setIssuer(teamDomain)
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime("2m")
      .sign(privateKey);
    const result = await validateCloudflareAccessJwt(new Headers({ "cf-access-jwt-assertion": token }), {
      CLOUDFLARE_ACCESS_JWT_REQUIRED: "true",
      CLOUDFLARE_ACCESS_AUDIENCE: audience,
      CLOUDFLARE_TEAM_DOMAIN: teamDomain
    });

    assert.deepEqual(result, { allowed: true, required: true, status: "valid" });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("covers disabled, missing configuration, and missing JWT outcomes", async () => {
  assert.deepEqual(
    await validateCloudflareAccessJwt(new Headers(), {}),
    { allowed: true, required: false, status: "disabled" }
  );
  assert.deepEqual(
    await validateCloudflareAccessJwt(new Headers(), {
      CLOUDFLARE_ACCESS_JWT_REQUIRED: "true"
    }),
    {
      allowed: false,
      required: true,
      status: "misconfigured",
      reason: "missing-cloudflare-access-config"
    }
  );
  assert.deepEqual(
    await validateCloudflareAccessJwt(new Headers(), {
      CLOUDFLARE_ACCESS_JWT_REQUIRED: "true",
      CLOUDFLARE_ACCESS_AUDIENCE: "synthetic-audience",
      CLOUDFLARE_TEAM_DOMAIN: "https://team.example.invalid"
    }),
    {
      allowed: false,
      required: true,
      status: "missing",
      reason: "missing-cloudflare-access-jwt"
    }
  );
});

test("production always requires an Access JWT when the opt-in flag is missing or false", async () => {
  const common = {
    NODE_ENV: "production",
    CLOUDFLARE_ACCESS_AUDIENCE: "synthetic-audience",
    CLOUDFLARE_TEAM_DOMAIN: "https://team.example.invalid"
  };

  for (const env of [
    common,
    { ...common, CLOUDFLARE_ACCESS_JWT_REQUIRED: "false" }
  ]) {
    assert.deepEqual(await validateCloudflareAccessJwt(new Headers(), env), {
      allowed: false,
      required: true,
      status: "missing",
      reason: "missing-cloudflare-access-jwt"
    });
  }
});

test("rejects malformed and invalid JWT-shaped assertions", async () => {
  const env = {
    CLOUDFLARE_ACCESS_JWT_REQUIRED: "true",
    CLOUDFLARE_ACCESS_AUDIENCE: "synthetic-audience",
    CLOUDFLARE_TEAM_DOMAIN: "https://team.example.invalid"
  };

  for (const token of ["synthetic-malformed", "invalid.header.signature"]) {
    const result = await validateCloudflareAccessJwt(
      new Headers({ "cf-access-jwt-assertion": token }),
      env
    );

    assert.equal(result.allowed, false);
    assert.equal(result.required, true);
    assert.equal(result.status, "invalid");
    assert.equal(result.reason, "invalid-cloudflare-access-jwt");
  }
});

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
