import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import { prisma } from "@bielos/database";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";
import { getCurrentSession } from "../lib/auth";
import { getSurface, trustedReturnTo } from "../lib/surface";

export const dynamic = "force-dynamic";

export default async function HomePage() {
  const requestHeaders = await headers();
  const surface = getSurface(requestHeaders);
  if (surface === "unknown") forbidden();
  const session = await getCurrentSession();
  if (!session) {
    const returnTo = trustedReturnTo(requestHeaders, surface) ?? (surface === "hub" ? "/admin/accounts" : "/");
    redirect(`/login?returnTo=${encodeURIComponent(returnTo)}`);
  }
  if (surface === "hub") {
    if (session.user.role !== "ADMIN") forbidden();
    redirect("/admin/accounts");
  }
  if (session.user.role !== "USER") forbidden();

  const projects = await prisma.userProjectGrant.findMany({
    where: { userId: session.user.id, user: { role: "USER", isActive: true, accountStatus: "ACTIVE" }, revokedAt: null, connection: { enabled: true } },
    orderBy: { connection: { name: "asc" } },
    select: { connection: { select: { name: true, description: true, launchUrl: true } } }
  });
  const csrf = createCsrfToken({ scope: "logout" });

  return (
    <>
      <a className="skip-link" href="#main-content">Ir para o conteúdo</a>
      <main className="admin-main">
      <header className="page-header">
        <div><p className="eyebrow">BielOS</p><h1>Projetos</h1></div>
        <div><a className="text-link" href="/account/security">Minha conta</a>
          <form action="/api/logout" method="post"><input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrf} /><button type="submit">Sair</button></form>
        </div>
      </header>
      <section id="main-content" className="project-list" tabIndex={-1} aria-label="Projetos autorizados">
        {projects.length ? projects.map(({ connection }) => (
          connection.launchUrl ? <a className="project-link" href={connection.launchUrl} key={connection.launchUrl}>
            <span className="row-main"><strong>{connection.name}</strong>{connection.description ? <span>{connection.description}</span> : null}</span>
            <span>Acessar</span>
          </a> : <article className="project-link" key={connection.name} aria-label={`${connection.name}: acesso em configuração`}>
            <span className="row-main"><strong>{connection.name}</strong>{connection.description ? <span>{connection.description}</span> : null}<span className="muted">Link de acesso ainda não configurado.</span></span>
            <span aria-hidden="true">Indisponível</span>
          </article>
        )) : <p className="muted">Nenhum projeto disponível.</p>}
      </section>
      </main>
    </>
  );
}
