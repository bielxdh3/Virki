export default function NotFoundPage() {
  return (
    <main className="auth-page">
      <section className="auth-panel" aria-labelledby="not-found-title">
        <p className="eyebrow">Virki</p>
        <h1 id="not-found-title">404</h1>
        <p>Página não encontrada.</p>
        <a className="button-primary" href="/login">Voltar ao início</a>
      </section>
    </main>
  );
}
