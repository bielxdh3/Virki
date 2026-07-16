import assert from "node:assert/strict";
import test from "node:test";
import { NextRequest } from "next/server";

import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";

import { POST } from "./route";

test("logout redirects to the configured public hub origin", async () => {
  const originalAccessRequired = process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED;
  const originalHubUrl = process.env.NEXT_PUBLIC_HUB_URL;

  try {
    process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = "false";
    process.env.NEXT_PUBLIC_HUB_URL = "https://hub.example.invalid";
    const formData = new FormData();
    formData.set(CSRF_FORM_FIELD_NAME, createCsrfToken());

    const response = await POST(new NextRequest("https://localhost:3001/api/logout", {
      method: "POST",
      body: formData
    }));

    assert.equal(response.status, 303);
    assert.equal(response.headers.get("location"), "https://hub.example.invalid/login");
  } finally {
    restoreEnvironmentVariable("CLOUDFLARE_ACCESS_JWT_REQUIRED", originalAccessRequired);
    restoreEnvironmentVariable("NEXT_PUBLIC_HUB_URL", originalHubUrl);
  }
});

function restoreEnvironmentVariable(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
    return;
  }

  process.env[name] = value;
}
