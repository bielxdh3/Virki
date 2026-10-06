import React from "react";

export const dynamic = "force-dynamic";

function getPortalUrl(value: string | undefined): string | null {
  if (!value?.trim()) return null;
  try {
    const url = new URL(value.trim());
    if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash) return null;
    return url.origin;
  } catch {
    return null;
  }
}

export default function PublicLandingPage() {
  const portalUrl = getPortalUrl(process.env.BIELOS_PORTAL_URL);
  return (
    <main className="public-page">
      <section className="public-panel" aria-labelledby="bielos-title">
        <p className="eyebrow">Identidade e acesso</p>
        <h1 id="bielos-title">BielOS</h1>
        <p>Identidade e acesso para projetos privados.</p>
        {portalUrl ? <a className="button-primary" href={portalUrl}>Entrar</a> : <p className="muted" role="status">A entrada ao portal está temporariamente indisponível. Tente novamente mais tarde.</p>}
      </section>
    </main>
  );
}
