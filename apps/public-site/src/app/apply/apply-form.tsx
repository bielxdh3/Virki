"use client";

import { useState } from "react";
import type { BielosLocale } from "@bielos/ui";

type ApplyCopy = {
  email: string;
  displayName: string;
  modules: string;
  reason: string;
  submit: string;
  unavailable: string;
  runtimeAvailable: string;
  runtimeUnavailable: string;
};

type ApplyModule = {
  key: string;
  name: string;
  available: boolean;
};

export function ApplyForm({
  locale,
  copy,
  modules,
  apiUrl
}: {
  locale: BielosLocale;
  copy: ApplyCopy;
  modules: readonly ApplyModule[];
  apiUrl: string;
}) {
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [selected, setSelected] = useState<Record<string, boolean>>({ gymforge: true });
  const [reasons, setReasons] = useState<Record<string, string>>({});
  const [status, setStatus] = useState<"idle" | "sending" | "accepted" | "unavailable">("idle");

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!apiUrl) {
      setStatus("unavailable");
      return;
    }

    setStatus("sending");
    const response = await fetch(apiUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        email,
        displayName,
        locale,
        modules: modules
          .filter((module) => selected[module.key])
          .map((module) => ({ key: module.key, reason: reasons[module.key] ?? "" }))
      })
    }).catch(() => null);

    setStatus(response?.ok ? "accepted" : "unavailable");
  }

  return (
    <form className="apply-form" onSubmit={submit}>
      <label>
        {copy.email}
        <input required maxLength={270} type="email" value={email} onChange={(event) => setEmail(event.target.value)} />
      </label>
      <label>
        {copy.displayName}
        <input maxLength={80} value={displayName} onChange={(event) => setDisplayName(event.target.value)} />
      </label>
      <fieldset>
        <legend>{copy.modules}</legend>
        {modules.map((module) => (
          <div className="apply-module" key={module.key}>
            <label>
              <input
                type="checkbox"
                checked={Boolean(selected[module.key])}
                onChange={(event) => setSelected((current) => ({ ...current, [module.key]: event.target.checked }))}
              />
              {module.name}
            </label>
            <span>{module.available ? copy.runtimeAvailable : copy.runtimeUnavailable}</span>
            {selected[module.key] && (
              <textarea
                required
                maxLength={1000}
                placeholder={copy.reason}
                value={reasons[module.key] ?? ""}
                onChange={(event) => setReasons((current) => ({ ...current, [module.key]: event.target.value }))}
              />
            )}
          </div>
        ))}
      </fieldset>
      <button type="submit" disabled={status === "sending" || !apiUrl}>{copy.submit}</button>
      {status === "accepted" && <p role="status">{locale === "pt-BR" ? "Recebemos sua solicitação." : "Your request was received."}</p>}
      {(status === "unavailable" || !apiUrl) && <p role="status">{copy.unavailable}</p>}
    </form>
  );
}
