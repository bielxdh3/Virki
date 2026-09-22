import React from "react";

const portalUrl = process.env.NEXT_PUBLIC_PORTAL_URL ?? "https://portal.biel.dev.br";

export default function PublicLandingPage() {
  return (
    <main className="public-page">
      <section className="public-panel" aria-labelledby="bielos-title">
        <p className="eyebrow">Identidade e acesso</p>
        <h1 id="bielos-title">BielOS</h1>
        <p>Identidade e acesso para projetos privados.</p>
        <a className="button-primary" href={portalUrl}>Entrar</a>
      </section>
    </main>
  );
}
