import assert from "node:assert/strict";
import { test } from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { RecoveryReviewDetails, recoveryNeedsAdministrativeReview } from "./recovery-review-details";

test("assisted recovery details show factor, independent approval, and escaped bounded comment", () => {
  const markup = renderToStaticMarkup(<RecoveryReviewDetails request={{
    recoveryProofs: ["TOTP"], recoveryAdminReview: true,
    recoveryComment: "Preciso recuperar <script>nao executar</script>"
  }} />);
  assert.match(markup, /Aplicativo autenticador \+ aprovação administrativa/u);
  assert.match(markup, /Preciso recuperar &lt;script&gt;nao executar&lt;\/script&gt;/u);
  assert.doesNotMatch(markup, /<script>/u);
});

test("two-factor request must not look like it needs an unrelated reviewer", () => {
  const markup = renderToStaticMarkup(<RecoveryReviewDetails request={{
    recoveryProofs: ["PASSKEY", "TOTP"], recoveryAdminReview: false
  }} />);
  assert.match(markup, /Passkey \+ Aplicativo autenticador/u);
  assert.doesNotMatch(markup, /aprovação administrativa/u);
  assert.equal(recoveryNeedsAdministrativeReview({ recoveryProofs: ["PASSKEY", "TOTP"], recoveryAdminReview: false }), false);
  assert.equal(recoveryNeedsAdministrativeReview({ recoveryProofs: ["TOTP"], recoveryAdminReview: true }), true);
});

test("legacy recovery has a nonconfusing method label and no optional comment", () => {
  const markup = renderToStaticMarkup(<RecoveryReviewDetails request={{ emailVerifiedAt: new Date(), recoveryProofs: [] }} />);
  assert.match(markup, /E-mail verificado \(fluxo anterior\)/u);
  assert.doesNotMatch(markup, /Comentário do solicitante/u);
});
