import React from "react";

export default function PublicNotFoundPage() {
  return (
    <main className="public-page">
      <section className="public-panel" aria-labelledby="not-found-title">
        <p className="eyebrow">Página não encontrada</p>
        <h1 id="not-found-title">404</h1>
        <p>Esta página não existe ou não está disponível.</p>
        <a className="button-primary" href="/">Voltar ao início</a>
      </section>
    </main>
  );
}
