import assert from "node:assert/strict";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import test from "node:test";
import { RecoveryProofStage, type RecoveryProof, type RecoveryProofActionState, type RecoveryPasskeyStartState } from "./recovery-proof-stage";

const verify = async (): Promise<RecoveryProofActionState> => ({ status: "error" });
const startPasskey = async (): Promise<RecoveryPasskeyStartState> => ({ status: "error" });

function render(requiredProofs: RecoveryProof[], verifiedProofs: RecoveryProof[], needsAdminReview = false, adminReviewed = false) {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, "React");
  Object.defineProperty(globalThis, "React", { configurable: true, value: React });
  try {
    return renderToStaticMarkup(<RecoveryProofStage
      csrf="csrf-value" csrfFieldName="csrfToken" requestId="request-value"
      requiredProofs={requiredProofs} verifiedProofs={verifiedProofs}
      needsAdminReview={needsAdminReview} adminReviewed={adminReviewed}
      verifyEmailAction={verify} verifyTotpAction={verify}
      startPasskeyAction={startPasskey} verifyPasskeyAction={async () => ({ status: "error" })}
    />);
  } finally {
    if (descriptor) Object.defineProperty(globalThis, "React", descriptor);
    else Reflect.deleteProperty(globalThis, "React");
  }
}

test("EMAIL + TOTP request renders exactly its required proof forms with bound request and CSRF fields", () => {
  const html = render(["EMAIL", "TOTP"], []);
  assert.match(html, /E-mail cadastrado/u);
  assert.match(html, /Aplicativo autenticador/u);
  assert.match(html, /name="csrfToken" value="csrf-value"/u);
  assert.match(html, /name="requestId" value="request-value"/u);
  assert.doesNotMatch(html, /Confirmar com passkey/u);
  assert.doesNotMatch(html, /aprovação de outro administrador ativo/u);
});

test("PASSKEY + TOTP request offers both proofs without an email verification dependency", () => {
  const html = render(["PASSKEY", "TOTP"], []);
  assert.match(html, /Confirmar com passkey/u);
  assert.match(html, /Aplicativo autenticador/u);
  assert.match(html, /confirme primeiro o e-mail ou o autenticador/u, "legacy non-discoverable keys require the other verified factor first");
  assert.doesNotMatch(html, /E-mail cadastrado/u);
});

test("PASSKEY + independent ADMIN review does not promise legacy-key fallback before the reviewer", () => {
  const html = render(["PASSKEY"], [], true);
  assert.doesNotMatch(html, /chave de segurança antiga/u);
});

test("verified proof is never re-requested and assisted request waits for independent admin", () => {
  const html = render(["EMAIL"], ["EMAIL"], true);
  assert.match(html, /E-mail cadastrado/u);
  assert.match(html, /Confirmado/u);
  assert.match(html, /precisa da aprovação de outro administrador ativo/u);
  assert.doesNotMatch(html, /name="code"/u);
  assert.doesNotMatch(html, /etapa de definição da nova senha/u);
});

test("completed server-confirmed proofs and approval permit the next password stage", () => {
  const html = render(["PASSKEY"], ["PASSKEY"], true, true);
  assert.match(html, /Aprovação administrativa confirmada/u);
  assert.match(html, /etapa de definição da nova senha/u);
  assert.doesNotMatch(html, /Confirmar com passkey/u);
});
