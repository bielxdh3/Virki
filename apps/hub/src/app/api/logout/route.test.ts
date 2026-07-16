import assert from "node:assert/strict";
import test from "node:test";
import { NextRequest } from "next/server";

import { SESSION_COOKIE_NAME } from "@bielos/auth";
import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";

import { POST } from "./route";

test("logout redirects to the configured public hub origin", async () => {
  const originalAccessRequired = process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED;
  const originalHubUrl = process.env.NEXT_PUBLIC_HUB_URL;
  const originalNodeEnv = process.env.NODE_ENV;

  try {
    process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = "false";
    process.env.NEXT_PUBLIC_HUB_URL = "https://hub.example.invalid";
    setEnvironmentVariable("NODE_ENV", "production");
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
    restoreEnvironmentVariable("NODE_ENV", originalNodeEnv);
  }
});

test("invalid production redirect configuration clears the cookie without an internal redirect", async () => {
  const originalAccessRequired = process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED;
  const originalHubUrl = process.env.NEXT_PUBLIC_HUB_URL;
  const originalNodeEnv = process.env.NODE_ENV;

  try {
    process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = "false";
    setEnvironmentVariable("NODE_ENV", "production");
    delete process.env.NEXT_PUBLIC_HUB_URL;
    const formData = new FormData();
    formData.set(CSRF_FORM_FIELD_NAME, createCsrfToken());

    const response = await POST(new NextRequest("http://hub:3001/api/logout", {
      method: "POST",
      body: formData
    }));
    const setCookie = response.headers.get("set-cookie") ?? "";

    assert.equal(response.status, 503);
    assert.equal(response.headers.get("location"), null);
    assert.equal(setCookie.startsWith(`${SESSION_COOKIE_NAME}=`), true);
    assert.equal(setCookie.includes("Max-Age=0"), true);
    assert.equal(setCookie.includes("HttpOnly"), true);
    assert.equal(setCookie.includes("Secure"), true);
    assert.equal(setCookie.includes("SameSite=lax"), true);
  } finally {
    restoreEnvironmentVariable("CLOUDFLARE_ACCESS_JWT_REQUIRED", originalAccessRequired);
    restoreEnvironmentVariable("NEXT_PUBLIC_HUB_URL", originalHubUrl);
    restoreEnvironmentVariable("NODE_ENV", originalNodeEnv);
  }
});

function restoreEnvironmentVariable(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
    return;
  }

  process.env[name] = value;
}

function setEnvironmentVariable(name: string, value: string): void {
  process.env[name] = value;
}
