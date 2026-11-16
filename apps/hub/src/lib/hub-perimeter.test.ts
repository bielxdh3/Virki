import assert from "node:assert/strict";
import test from "node:test";
import { isNativeHubPerimeterEnabled } from "./hub-perimeter";
import { validateHubCloudflareAccess } from "./cloudflare-access";

test("native perimeter requires the exact explicit opt-in", () => {
  for (const NODE_ENV of ["production", "development", "test"]) {
    assert.equal(isNativeHubPerimeterEnabled({ NODE_ENV }), false);
    for (const value of ["", "true", "enabled", "NATIVE", " native", "native ", "access", "cloudflare"]) {
      assert.equal(isNativeHubPerimeterEnabled({ NODE_ENV, VIRKI_HUB_PERIMETER_MODE: value }), false, `${NODE_ENV}:${value}`);
    }
    assert.equal(isNativeHubPerimeterEnabled({ NODE_ENV, VIRKI_HUB_PERIMETER_MODE: "native" }), true);
  }
});

test("native perimeter explicitly disables only the external Access JWT, not app authentication", async () => {
  const before = process.env.VIRKI_HUB_PERIMETER_MODE;
  try {
    process.env.VIRKI_HUB_PERIMETER_MODE = "native";
    const result = await validateHubCloudflareAccess(new Headers({ "cf-access-jwt-assertion": "forged" }), "native-test");
    assert.deepEqual(result, { allowed: true, required: false, status: "disabled" });
    // The separate ADMIN session/role/elevation guards are intentionally NOT
    // replaced by an Access assertion in this mode.
  } finally {
    if (before === undefined) delete process.env.VIRKI_HUB_PERIMETER_MODE;
    else process.env.VIRKI_HUB_PERIMETER_MODE = before;
  }
});
