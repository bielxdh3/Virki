import assert from "node:assert/strict";
import test from "node:test";
import {
  isNativeHubPerimeterEnabled,
  NATIVE_EDGE_PROOF_HEADER,
  verifyNativeHubEdgeProof
} from "./hub-perimeter";
import { validateHubCloudflareAccess } from "./cloudflare-access";

const VALID_EDGE_SECRET = "native-edge-test-value-".repeat(2);

test("native perimeter fails closed in production without explicit Access opt-out and edge secret", () => {
  assert.equal(isNativeHubPerimeterEnabled({ NODE_ENV: "production" }), false);
  for (const value of ["", "true", "enabled", "NATIVE", " native", "native ", "access", "cloudflare"]) {
    assert.equal(
      isNativeHubPerimeterEnabled({
        NODE_ENV: "production",
        VIRKI_HUB_PERIMETER_MODE: value,
        CLOUDFLARE_ACCESS_JWT_REQUIRED: "false",
        VIRKI_NATIVE_EDGE_PROOF_SECRET: VALID_EDGE_SECRET
      }),
      false,
      `production:${value}`
    );
  }
  // Contradicting CLOUDFLARE_ACCESS_JWT_REQUIRED=true or missing/short edge secret must fail closed
  assert.equal(
    isNativeHubPerimeterEnabled({
      NODE_ENV: "production",
      VIRKI_HUB_PERIMETER_MODE: "native",
      CLOUDFLARE_ACCESS_JWT_REQUIRED: "true",
      VIRKI_NATIVE_EDGE_PROOF_SECRET: VALID_EDGE_SECRET
    }),
    false
  );
  assert.equal(
    isNativeHubPerimeterEnabled({
      NODE_ENV: "production",
      VIRKI_HUB_PERIMETER_MODE: "native",
      VIRKI_NATIVE_EDGE_PROOF_SECRET: VALID_EDGE_SECRET
    }),
    false
  );
  for (const badSecret of [undefined, "", "   ", "too-short", "a".repeat(31)]) {
    assert.equal(
      isNativeHubPerimeterEnabled({
        NODE_ENV: "production",
        VIRKI_HUB_PERIMETER_MODE: "native",
        CLOUDFLARE_ACCESS_JWT_REQUIRED: "false",
        VIRKI_NATIVE_EDGE_PROOF_SECRET: badSecret
      }),
      false,
      `bad-secret:${String(badSecret)}`
    );
  }
  assert.equal(
    isNativeHubPerimeterEnabled({
      NODE_ENV: "production",
      VIRKI_HUB_PERIMETER_MODE: "native",
      CLOUDFLARE_ACCESS_JWT_REQUIRED: "false",
      VIRKI_NATIVE_EDGE_PROOF_SECRET: VALID_EDGE_SECRET
    }),
    true
  );
  // Non-production keeps explicit local/E2E opt-in
  for (const NODE_ENV of ["development", "test"]) {
    assert.equal(isNativeHubPerimeterEnabled({ NODE_ENV, VIRKI_HUB_PERIMETER_MODE: "native" }), true);
  }
});

test("verifyNativeHubEdgeProof rejects missing, empty, or forged edge proofs", () => {
  const env = { VIRKI_NATIVE_EDGE_PROOF_SECRET: VALID_EDGE_SECRET };
  assert.equal(verifyNativeHubEdgeProof(new Headers(), env), false);
  assert.equal(verifyNativeHubEdgeProof(new Headers({ [NATIVE_EDGE_PROOF_HEADER]: "" }), env), false);
  assert.equal(verifyNativeHubEdgeProof(new Headers({ [NATIVE_EDGE_PROOF_HEADER]: "forged" }), env), false);
  assert.equal(verifyNativeHubEdgeProof(new Headers({ [NATIVE_EDGE_PROOF_HEADER]: VALID_EDGE_SECRET }), {}), false);
  assert.equal(verifyNativeHubEdgeProof(new Headers({ [NATIVE_EDGE_PROOF_HEADER]: VALID_EDGE_SECRET }), env), true);
});

test("native perimeter in production denies requests lacking a verified edge proof", async () => {
  const keys = ["NODE_ENV", "VIRKI_HUB_PERIMETER_MODE", "CLOUDFLARE_ACCESS_JWT_REQUIRED", "VIRKI_NATIVE_EDGE_PROOF_SECRET"] as const;
  const before = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
  try {
    Object.assign(process.env, {
      NODE_ENV: "production",
      VIRKI_HUB_PERIMETER_MODE: "native",
      CLOUDFLARE_ACCESS_JWT_REQUIRED: "false",
      VIRKI_NATIVE_EDGE_PROOF_SECRET: VALID_EDGE_SECRET
    });
    const missing = await validateHubCloudflareAccess(new Headers({ "cf-access-jwt-assertion": "forged" }), "native-test");
    assert.equal(missing.allowed, false);
    const forged = await validateHubCloudflareAccess(new Headers({ [NATIVE_EDGE_PROOF_HEADER]: "forged" }), "native-test");
    assert.equal(forged.allowed, false);
    const allowed = await validateHubCloudflareAccess(new Headers({ [NATIVE_EDGE_PROOF_HEADER]: VALID_EDGE_SECRET }), "native-test");
    assert.deepEqual(allowed, { allowed: true, required: false, status: "disabled" });
  } finally {
    for (const k of keys) {
      if (before[k] === undefined) delete process.env[k];
      else Reflect.set(process.env, k, before[k]);
    }
  }
});
