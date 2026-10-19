import assert from "node:assert/strict";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import PublicLandingPage from "./page";

test("public landing omits the portal link until an explicit URL is configured", () => {
  const previous = process.env.VIRKI_PORTAL_URL;
  delete process.env.VIRKI_PORTAL_URL;
  const markup = renderToStaticMarkup(createElement(PublicLandingPage));
  if (previous !== undefined) process.env.VIRKI_PORTAL_URL = previous;
  assert.equal((markup.match(/<main\b/gu) ?? []).length, 1);
  assert.equal((markup.match(/<section\b/gu) ?? []).length, 1);
  assert.equal((markup.match(/<a\b/gu) ?? []).length, 0);
  assert.match(markup, /<h1\b[^>]*>Virki<\/h1>/u);
  assert.match(markup, /temporariamente indisponível/u);
  assert.match(markup, /Tente novamente mais tarde/u);
});

test("public landing uses the configured HTTPS portal origin", () => {
  const previous = process.env.VIRKI_PORTAL_URL;
  process.env.VIRKI_PORTAL_URL = "https://portal.example.test/";
  const markup = renderToStaticMarkup(createElement(PublicLandingPage));
  if (previous === undefined) delete process.env.VIRKI_PORTAL_URL;
  else process.env.VIRKI_PORTAL_URL = previous;
  assert.match(markup, /href="https:\/\/portal\.example\.test"/u);
  assert.match(markup, />Entrar<\/a>/u);
});

test("public landing rejects unsafe portal URLs", () => {
  const previous = process.env.VIRKI_PORTAL_URL;
  process.env.VIRKI_PORTAL_URL = "https://user:secret@portal.example.test";
  const markup = renderToStaticMarkup(createElement(PublicLandingPage));
  if (previous === undefined) delete process.env.VIRKI_PORTAL_URL;
  else process.env.VIRKI_PORTAL_URL = previous;
  assert.doesNotMatch(markup, /href=/u);
});

test("public site CSP is strict: no framing, plugins, base rewriting or form posts, and eval only in development", async () => {
  // @ts-expect-error -- plain .mjs config module without type declarations
  const { buildPublicContentSecurityPolicy } = (await import("../../next.config.mjs")) as { buildPublicContentSecurityPolicy: (nodeEnv?: string) => string };
  const production = buildPublicContentSecurityPolicy("production");
  for (const directive of ["default-src 'self'", "object-src 'none'", "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'", "upgrade-insecure-requests"]) {
    assert.ok(production.split("; ").includes(directive), directive);
  }
  assert.doesNotMatch(production, /unsafe-eval/u);
  assert.match(buildPublicContentSecurityPolicy("development"), /'unsafe-eval'/u);
});

test("robots safely falls back for empty, malformed or non-origin public URL configuration", () => {
  for (const value of ["", " ", "invalid", "javascript:alert(1)", "https://user:secret@example.invalid", "https://example.invalid/path", "https://example.invalid?query=1", "https://public.example.invalid/"]) {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "-e", `
      import robots from './apps/public-site/src/app/robots.ts';
      console.log(JSON.stringify((robots.default ?? robots)()));
    `], { encoding: "utf8", windowsHide: true, env: { ...process.env, PUBLIC_SITE_URL: value } });
    assert.equal(result.status, 0, result.stderr);
    const metadata = JSON.parse(result.stdout);
    const expectedOrigin = value === "https://public.example.invalid/" ? "https://public.example.invalid" : "https://biel.dev.br";
    assert.equal(metadata.sitemap, `${expectedOrigin}/sitemap.xml`);
    assert.equal(metadata.host, expectedOrigin);
  }
});
