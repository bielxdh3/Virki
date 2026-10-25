"use client";

import { startAuthentication } from "@simplewebauthn/browser";
import { useState } from "react";

export function PasskeyLogin({ returnTo }: { returnTo: string }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");

  async function login() {
    setError("");
    setPending(true);
    try {
      const start = await fetch("/api/passkeys", { method: "POST", headers: { "content-type": "application/json" }, credentials: "same-origin", cache: "no-store", body: JSON.stringify({ action: "login-options", email, password }) });
      if (!start.ok) throw new Error("request rejected");
      const { options } = await start.json();
      const response = await startAuthentication({ optionsJSON: options });
      const finish = await fetch("/api/passkeys", { method: "POST", headers: { "content-type": "application/json" }, credentials: "same-origin", cache: "no-store", body: JSON.stringify({ action: "login-verify", response }) });
      if (!finish.ok) throw new Error("request rejected");
      window.location.assign(returnTo);
    } catch {
      setError("A passkey não foi validada. Tente novamente ou entre com sua senha.");
      setPending(false);
    }
  }

  return <section className="form-stack" aria-label="Entrar com passkey">
    <h2>Entrar com passkey</h2>
    <p className="muted">Use a biometria, PIN ou chave de segurança do seu dispositivo. Sua senha continua disponível abaixo.</p>
    <label>E-mail (opcional, para selecionar uma chave não detectável)<input type="email" autoComplete="username webauthn" value={email} onChange={event => setEmail(event.target.value)} maxLength={320} disabled={pending} /></label>
    {email && <label>Senha para selecionar a chave cadastrada<input type="password" autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} maxLength={256} disabled={pending} /></label>}
    <button className="button-primary" type="button" disabled={pending || Boolean(email && !password)} onClick={login}>{pending ? "Verificando passkey…" : "Entrar com passkey"}</button>
    {error && <p className="form-error" role="alert">{error}</p>}
  </section>;
}
