import assert from "node:assert/strict";
import test from "node:test";
import { NextRequest } from "next/server";

import { POST } from "./route";

test("audit export rejects requests without the CSRF token before reading audit data", async () => {
  const originalAccessRequired = process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED;

  try {
    process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = "false";
    const response = await POST(new NextRequest("http://localhost:3001/api/core/audit/export", {
      method: "POST",
      body: new FormData()
    }));

    assert.equal(response.status, 403);
  } finally {
    if (originalAccessRequired === undefined) {
      delete process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED;
    } else {
      process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = originalAccessRequired;
    }
  }
});
