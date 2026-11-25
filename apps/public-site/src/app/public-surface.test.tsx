import assert from "node:assert/strict";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import PublicLandingPage from "./page";
import PublicNotFoundPage from "./not-found";
import { buildPublicContentSecurityPolicy } from "../public-csp";

test("public security.txt publishes the authorized contact and an unexpired RFC 9116 record", () => {
  const contents = readFileSync(new URL("../../public/.well-known/security.txt", import.meta.url), "utf8");
  const lines = contents.trimEnd().split(/\r?\n/u);
  assert.deepEqual(lines.filter((line) => line.startsWith("Contact:")), ["Contact: mailto:gabriel@biel.dev.br"]);
  assert.deepEqual(lines.filter((line) => line.startsWith("Canonical:")), ["Canonical: https://biel.dev.br/.well-known/security.txt"]);
  const expires = lines.filter((line) => line.startsWith("Expires: "));
  assert.equal(expires.length, 1);
  const expiration = Date.parse(expires[0].slice("Expires: ".length));
  assert.ok(Number.isFinite(expiration) && expiration > Date.now(), "Renew the authorized security contact before its expiration.");
});

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

test("public site CSP authorizes its framework scripts with a nonce and retains the existing restrictions", () => {
  const production = buildPublicContentSecurityPolicy("production", "testNonce123");
  assert.equal(production.split("; ").find((directive) => directive.startsWith("script-src ")), "script-src 'self' 'nonce-testNonce123'");
  for (const directive of ["default-src 'self'", "style-src 'self'", "img-src 'self' data:", "font-src 'self'", "connect-src 'self'", "object-src 'none'", "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'", "upgrade-insecure-requests"]) {
    assert.ok(production.split("; ").includes(directive), directive);
  }
  assert.doesNotMatch(production, /unsafe-eval/u);
  const development = buildPublicContentSecurityPolicy("development", "testNonce123");
  assert.equal(development.split("; ").find((directive) => directive.startsWith("script-src ")), "script-src 'self' 'nonce-testNonce123' 'unsafe-eval'");
  assert.doesNotMatch(development, /upgrade-insecure-requests/u);
});

test("production public CSP cannot authorize arbitrary inline styles on the 404 page", () => {
  const policy = buildPublicContentSecurityPolicy("production", "testNonce123");
  assert.ok(policy.split("; ").includes("style-src 'self'"));
  assert.doesNotMatch(policy, /'unsafe-inline'/u);
  const html = renderToStaticMarkup(createElement(PublicNotFoundPage));
  assert.match(html, /404/u);
  assert.match(html, /Voltar ao início/u);
  assert.doesNotMatch(html, /\sstyle=/u);
  assert.doesNotMatch(html, /<style\b/u);
});

test("development Next overlay styles stay isolated from strict production CSP", () => {
  const development = buildPublicContentSecurityPolicy("development", "testNonce123");
  const production = buildPublicContentSecurityPolicy("production", "testNonce123");
  const unspecified = buildPublicContentSecurityPolicy(undefined, "testNonce123");
  assert.ok(development.split("; ").includes("style-src 'self' 'unsafe-inline'"),
    "the local Next development overlay injects inline styles and must not generate browser CSP errors");
  assert.ok(production.split("; ").includes("style-src 'self'"));
  assert.ok(unspecified.split("; ").includes("style-src 'self'"));
  assert.doesNotMatch(production, /'unsafe-inline'/u);
  assert.doesNotMatch(unspecified, /'unsafe-inline'/u);
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
