import assert from "node:assert/strict";
import test from "node:test";
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
