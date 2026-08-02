"use client";

import { useEffect, useState } from "react";

export function VerifyApplication({ endpoint }: { endpoint: string }) {
  const [status, setStatus] = useState<"pending" | "success" | "failure">("pending");

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
          <h1>{status === "success" ? "E-mail verificado" : status === "pending" ? "Verificando" : "Link indisponível"}</h1>
          <p className="description">
            {status === "success" ? "Sua solicitação pode seguir para análise do owner." : "Não foi possível confirmar este link."}
          </p>
          <a className="secondary-button" href="/">Voltar</a>
        </section>
      </section>
    </main>
  );
}
