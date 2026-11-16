import assert from "node:assert/strict";
import test from "node:test";
import { isNativeHubPerimeterEnabled } from "./hub-perimeter";
import { validateHubCloudflareAccess } from "./cloudflare-access";

test("native perimeter requires explicit native mode and Access opt-out in production without an edge secret", () => {
  assert.equal(isNativeHubPerimeterEnabled({ NODE_ENV: "production" }), false);
  for (const value of ["", "true", "enabled", "NATIVE", " native", "native ", "access", "cloudflare"]) {
    assert.equal(
      isNativeHubPerimeterEnabled({
        NODE_ENV: "production",
        VIRKI_HUB_PERIMETER_MODE: value,
        CLOUDFLARE_ACCESS_JWT_REQUIRED: "false"
      }),
      false,
      `production:${value}`
    );
  }
  // Contradicting CLOUDFLARE_ACCESS_JWT_REQUIRED=true or omitting it must fail closed to Access.
  assert.equal(
    isNativeHubPerimeterEnabled({
      NODE_ENV: "production",
      VIRKI_HUB_PERIMETER_MODE: "native",
      CLOUDFLARE_ACCESS_JWT_REQUIRED: "true"
    }),
    false
  );
  assert.equal(
    isNativeHubPerimeterEnabled({
      NODE_ENV: "production",
      VIRKI_HUB_PERIMETER_MODE: "native"
    }),
    false
  );
  assert.equal(
    isNativeHubPerimeterEnabled({
      NODE_ENV: "production",
      VIRKI_HUB_PERIMETER_MODE: "native",
      CLOUDFLARE_ACCESS_JWT_REQUIRED: "false"
    }),
    true
  );
  // Non-production keeps explicit local/E2E opt-in.
  for (const NODE_ENV of ["development", "test"]) {
    assert.equal(isNativeHubPerimeterEnabled({ NODE_ENV, VIRKI_HUB_PERIMETER_MODE: "native" }), true);
  }
});

test("native perimeter in production allows downstream Hub routes without Access JWT or edge proof", async () => {
  const keys = ["NODE_ENV", "VIRKI_HUB_PERIMETER_MODE", "CLOUDFLARE_ACCESS_JWT_REQUIRED"] as const;
  const before = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
  try {
    Object.assign(process.env, {
      NODE_ENV: "production",
      VIRKI_HUB_PERIMETER_MODE: "native",
      CLOUDFLARE_ACCESS_JWT_REQUIRED: "false"
    });
    const allowed = await validateHubCloudflareAccess(new Headers(), "native-test");
    assert.deepEqual(allowed, { allowed: true, required: false, status: "disabled" });
    const withForgedAccess = await validateHubCloudflareAccess(
      new Headers({ "cf-access-jwt-assertion": "forged" }),
      "native-test"
    );
    assert.deepEqual(withForgedAccess, { allowed: true, required: false, status: "disabled" });
  } finally {
    for (const k of keys) {
      if (before[k] === undefined) delete process.env[k];
      else Reflect.set(process.env, k, before[k]);
    }
  }
});
