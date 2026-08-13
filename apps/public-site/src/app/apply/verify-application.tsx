"use client";

import React, { useEffect, useState } from "react";
import type { BielosLocale } from "@bielos/ui";

const copy = {
  "pt-BR": {
    verified: "E-mail verificado",
    verifying: "Verificando",
    unavailable: "Link indisponível",
    success: "Sua solicitação pode seguir para análise do owner.",
    failure: "Não foi possível confirmar este link.",
    back: "Voltar"
  },
  en: {
    verified: "Email verified",
    verifying: "Verifying",
    unavailable: "Link unavailable",
    success: "Your request can proceed to owner review.",
    failure: "This link could not be confirmed.",
    back: "Back"
  }
} satisfies Record<BielosLocale, Record<string, string>>;

export function VerifyApplication({ endpoint, locale }: { endpoint: string; locale: BielosLocale }) {
  const [status, setStatus] = useState<"pending" | "success" | "failure">("pending");
  const t = copy[locale];

  useEffect(() => {
    const token = new URLSearchParams(window.location.search).get("token");
    if (!endpoint || !token) {
      setStatus("failure");
      return;
    }
    void fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token })
    }).then((response) => setStatus(response.ok ? "success" : "failure")).catch(() => setStatus("failure"));
  }, [endpoint]);

  return (
    <main className="os-screen">
      <section className="desktop-shell apply-shell">
        <section className="apply-panel" aria-live="polite">
          <p className="eyebrow">BielOS</p>
          <h1>{status === "success" ? t.verified : status === "pending" ? t.verifying : t.unavailable}</h1>
          <p className="description">
            {status === "success" ? t.success : t.failure}
          </p>
          <a className="secondary-button" href="/">{t.back}</a>
        </section>
      </section>
    </main>
  );
}
