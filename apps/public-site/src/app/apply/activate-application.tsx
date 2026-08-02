"use client";

import { useState } from "react";

export function ActivateApplication({ endpoint }: { endpoint: string }) {
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [status, setStatus] = useState<"idle" | "sending" | "success" | "failure">("idle");

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
          <h1>Ativar conta</h1>
          {status === "success" ? (
            <p className="description">Conta ativada. Entre pelo hub privado.</p>
          ) : (
            <form className="apply-form" onSubmit={submit}>
              <label>Senha<input required minLength={12} maxLength={128} type="password" value={password} onChange={(event) => setPassword(event.target.value)} /></label>
              <label>Confirme a senha<input required minLength={12} maxLength={128} type="password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></label>
              <button type="submit" disabled={status === "sending"}>Criar senha</button>
              {status === "failure" && <p role="status">Link inválido ou indisponível.</p>}
            </form>
          )}
          <a className="secondary-button" href="/">Voltar</a>
        </section>
      </section>
    </main>
  );
}
