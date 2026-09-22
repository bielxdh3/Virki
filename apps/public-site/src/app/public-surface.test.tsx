import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import PublicLandingPage from "./page";

test("public landing contains only BielOS identity and the portal entry", () => {
  const markup = renderToStaticMarkup(createElement(PublicLandingPage));
  assert.match(markup, /BielOS/u);
  assert.match(markup, /portal\.biel\.dev\.br/u);
  for (const oldProduct of ["GymForge", "Módulos", "Dashboard", "Auditoria", "Cadastro"]) assert.doesNotMatch(markup, new RegExp(oldProduct, "iu"));
});
