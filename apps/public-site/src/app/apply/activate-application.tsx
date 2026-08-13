"use client";

import React, { useState } from "react";
import type { BielosLocale } from "@bielos/ui";

const copy = {
  "pt-BR": {
    title: "Ativar conta",
    success: "Conta ativada. Entre pelo hub privado.",
    password: "Senha",
    confirmation: "Confirme a senha",
    submit: "Criar senha",
    failure: "Link inválido ou indisponível.",
    back: "Voltar"
  },
  en: {
    title: "Activate account",
    success: "Account activated. Sign in through the private hub.",
    password: "Password",
    confirmation: "Confirm password",
    submit: "Create password",
    failure: "Link invalid or unavailable.",
    back: "Back"
  }
} satisfies Record<BielosLocale, Record<string, string>>;

export function ActivateApplication({ endpoint, locale }: { endpoint: string; locale: BielosLocale }) {
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [status, setStatus] = useState<"idle" | "sending" | "success" | "failure">("idle");
  const t = copy[locale];

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const token = new URLSearchParams(window.location.search).get("token");
    if (!endpoint || !token || password !== confirmation) {
      setStatus("failure");
      return;
    }
    setStatus("sending");
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token, password })
    }).catch(() => null);
    setStatus(response?.ok ? "success" : "failure");
  }

  return (
    <main className="os-screen">
      <section className="desktop-shell apply-shell">
        <section className="apply-panel">
          <p className="eyebrow">BielOS</p>
          <h1>{t.title}</h1>
          {status === "success" ? (
            <p className="description">{t.success}</p>
          ) : (
            <form className="apply-form" onSubmit={submit}>
              <label>{t.password}<input required minLength={12} maxLength={128} type="password" autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)} /></label>
              <label>{t.confirmation}<input required minLength={12} maxLength={128} type="password" autoComplete="new-password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></label>
              <button type="submit" disabled={status === "sending"}>{t.submit}</button>
              {status === "failure" && <p role="status">{t.failure}</p>}
            </form>
          )}
          <a className="secondary-button" href="/">{t.back}</a>
        </section>
      </section>
    </main>
  );
}
