"use client";

import { startRegistration } from "@simplewebauthn/browser";
import { useState } from "react";

type PasskeyRow = { id: string; name: string; createdAt: string; lastUsedAt: string | null; backupEligible: boolean; backupState: boolean };

export function PasskeyManager({ csrfToken, initialPasskeys, requiresTotp }: { csrfToken: string; initialPasskeys: PasskeyRow[]; requiresTotp: boolean }) {
  const [passkeys, setPasskeys] = useState(initialPasskeys);
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [name, setName] = useState("");
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  async function post(body: Record<string, unknown>) {
    const response = await fetch("/api/passkeys", { method: "POST", headers: { "content-type": "application/json" }, cache: "no-store", credentials: "same-origin", body: JSON.stringify({ ...body, csrfToken }) });
    if (!response.ok) throw new Error("rejected");
    return response.json();
  }

  async function run(action: "register" | "rename" | "revoke", id?: string) {
    setError(""); setMessage(""); setPending(true);
    try {
      if (!password) throw new Error("password required");
      if (action === "register") {
        if (!name.trim()) throw new Error("name required");
        const { options } = await post({ action: "register-options", password, totpCode });
        const response = await startRegistration({ optionsJSON: options });
        await post({ action: "register-verify", response, name });
        setMessage("Passkey cadastrada com sucesso.");
      } else {
        await post({ action, id, password, name, totpCode });
        if (action === "revoke") setPasskeys(current => current.filter(item => item.id !== id));
        if (action === "rename") setPasskeys(current => current.map(item => item.id === id ? { ...item, name: name.trim() } : item));
        setMessage(action === "revoke" ? "Passkey revogada." : "Nome da passkey atualizado.");
      }
      setPassword(""); setName(""); setTotpCode("");
      if (action === "register") window.location.reload();
    } catch { setError("Não foi possível confirmar a alteração. Confira sua senha e tente novamente."); }
    finally { setPending(false); }
  }

  return <section className="surface" aria-labelledby="passkey-title">
    <h2 id="passkey-title">Passkeys ({passkeys.length})</h2>
    <p>Use passkeys no portal para entrar com o dispositivo ou uma chave de segurança. Sua senha e os métodos de recuperação continuam ativos. Passkeys sincronizadas podem existir em vários aparelhos.</p>
    <div className="form-stack">
      <label>Senha atual para autorizar alterações<input type="password" autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} maxLength={256} disabled={pending} /></label>
      {requiresTotp && <label>Código atual do aplicativo autenticador<input inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} value={totpCode} onChange={event => setTotpCode(event.target.value)} disabled={pending} /></label>}
      <label>Nome da passkey<input value={name} onChange={event => setName(event.target.value)} maxLength={80} disabled={pending} placeholder="Ex.: notebook pessoal" /></label>
      <button type="button" disabled={pending || !password || (requiresTotp && totpCode.length !== 6) || !name.trim() || passkeys.length >= 20} onClick={() => run("register")}>{pending ? "Aguarde…" : "Adicionar passkey"}</button>
    </div>
    {message && <p className="form-success" role="status">{message}</p>}
    {error && <p className="form-error" role="alert">{error}</p>}
    {passkeys.length ? <div className="row-list">{passkeys.map(item => <article className="list-row" key={item.id}>
      <div className="row-main"><strong>{item.name}</strong><span>Criada {new Date(item.createdAt).toLocaleDateString("pt-BR")} · {item.backupEligible ? item.backupState ? "Sincronizada" : "Pode ser sincronizada" : "Vinculada ao autenticador"}{item.lastUsedAt ? ` · Último uso ${new Date(item.lastUsedAt).toLocaleDateString("pt-BR")}` : ""}</span></div>
      <div className="row-actions"><button type="button" disabled={pending || !password || (requiresTotp && totpCode.length !== 6) || !name.trim()} onClick={() => run("rename", item.id)} aria-label={`Renomear ${item.name} com o nome informado`}>Renomear</button><button type="button" className="button-danger" disabled={pending || !password || (requiresTotp && totpCode.length !== 6)} onClick={() => run("revoke", item.id)} aria-label={`Revogar ${item.name}`}>Revogar</button></div>
    </article>)}</div> : <p className="muted">Nenhuma passkey cadastrada.</p>}
    <p className="muted">Perdeu todas as passkeys? Entre com sua senha e a verificação existente. Para remover uma passkey é necessário confirmar sua senha.</p>
  </section>;
}
