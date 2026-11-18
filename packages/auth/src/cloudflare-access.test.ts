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
      .setNotBefore("0s")
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

test("production rejects HTTP and malformed Cloudflare JWKS origins while isolated loopback HTTP remains supported", async () => {
  const common = {
    NODE_ENV: "production",
    CLOUDFLARE_ACCESS_JWT_REQUIRED: "true",
    CLOUDFLARE_ACCESS_AUDIENCE: "synthetic-audience"
  };
  for (const teamDomain of [
    "http://team.example.invalid",
    "https://user:password@team.example.invalid",
    "https://team.example.invalid/path",
    "https://team.example.invalid?next=invalid",
    "https://127.0.0.1",
    "https://team.example.invalid:8443"
  ]) {
    assert.deepEqual(await validateCloudflareAccessJwt(new Headers(), { ...common, CLOUDFLARE_TEAM_DOMAIN: teamDomain }), {
      allowed: false,
      required: true,
      status: "misconfigured",
      reason: "invalid-cloudflare-access-config"
    }, teamDomain);
  }

  assert.deepEqual(await validateCloudflareAccessJwt(new Headers(), {
    CLOUDFLARE_ACCESS_JWT_REQUIRED: "true",
    CLOUDFLARE_ACCESS_AUDIENCE: "synthetic-audience",
    CLOUDFLARE_TEAM_DOMAIN: "http://127.0.0.1:3010"
  }), {
    allowed: false,
    required: true,
    status: "missing",
    reason: "missing-cloudflare-access-jwt"
  });
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


test("Access rejects signed tokens with missing temporal claims or invalid time boundaries", async () => {
  const teamDomain = "https://temporal-jwt-test.example.invalid";
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwk = await exportJWK(publicKey);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response(JSON.stringify({ keys: [{ ...jwk, kid: "time-key", use: "sig", alg: "RS256" }] }))) as typeof fetch;
  try {
    const now = Math.floor(Date.now() / 1000);
    const valid = { iat: now - 10, nbf: now - 10, exp: now + 60 };
    for (const claims of [{ iat: valid.iat, nbf: valid.nbf }, { nbf: valid.nbf, exp: valid.exp }, { iat: valid.iat, exp: valid.exp }, { ...valid, exp: now }, { ...valid, nbf: now + 60 }, { ...valid, iat: now + 60 }]) {
      const token = await new SignJWT(claims).setProtectedHeader({ alg: "RS256", kid: "time-key" }).setIssuer(teamDomain).setAudience("time-audience").sign(privateKey);
      const result = await validateCloudflareAccessJwt(new Headers({ "cf-access-jwt-assertion": token }), { CLOUDFLARE_ACCESS_JWT_REQUIRED: "true", CLOUDFLARE_ACCESS_AUDIENCE: "time-audience", CLOUDFLARE_TEAM_DOMAIN: teamDomain });
      assert.equal(result.allowed, false, JSON.stringify(claims));
    }
  } finally { globalThis.fetch = originalFetch; }
});

test("Access tolerates at most 30 seconds of future iat and nbf, but not expired tokens", async () => {
  const teamDomain = "https://skew-jwt-test.example.invalid";
  const audience = "skew-test-audience";
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwk = await exportJWK(publicKey);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response(JSON.stringify({ keys: [{ ...jwk, kid: "skew-key", use: "sig", alg: "RS256" }] }))) as typeof fetch;
  try {
    const now = Math.floor(Date.now() / 1000);
    const env = { CLOUDFLARE_ACCESS_JWT_REQUIRED: "true", CLOUDFLARE_ACCESS_AUDIENCE: audience, CLOUDFLARE_TEAM_DOMAIN: teamDomain };
    for (const [claims, allowed] of [
      [{ iat: now + 15, nbf: now + 15, exp: now + 90 }, true],
      // The verification clock advances independently inside jose. Use a
      // margin above the 30s policy so parallel CI load cannot turn an
      // originally 31s-future claim into an accepted 30s-future claim.
      [{ iat: now + 45, nbf: now, exp: now + 90 }, false],
      [{ iat: now, nbf: now + 45, exp: now + 90 }, false],
      [{ iat: now - 60, nbf: now - 60, exp: now - 1 }, false]
    ] as const) {
      const token = await new SignJWT(claims).setProtectedHeader({ alg: "RS256", kid: "skew-key" }).setIssuer(teamDomain).setAudience(audience).sign(privateKey);
      const result = await validateCloudflareAccessJwt(new Headers({ "cf-access-jwt-assertion": token }), env);
      assert.equal(result.allowed, allowed, JSON.stringify(claims));
    }
    const skewedClaims = { iat: now + 15, nbf: now + 15, exp: now + 90 };
    const otherSigner = (await generateKeyPair("RS256")).privateKey;
    for (const [issuer, tokenAudience, signer] of [
      ["https://other.example.invalid", audience, privateKey],
      [teamDomain, "other-audience", privateKey],
      [teamDomain, audience, otherSigner]
    ] as const) {
      const token = await new SignJWT(skewedClaims).setProtectedHeader({ alg: "RS256", kid: "skew-key" }).setIssuer(issuer).setAudience(tokenAudience).sign(signer);
      const result = await validateCloudflareAccessJwt(new Headers({ "cf-access-jwt-assertion": token }), env);
      assert.equal(result.allowed, false, `${issuer}/${tokenAudience}`);
    }
  } finally { globalThis.fetch = originalFetch; }
});
