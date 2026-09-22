import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import { prisma } from "@bielos/database";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";
import { getCurrentSession } from "../lib/auth";
import { getSurface } from "../lib/surface";

export const dynamic = "force-dynamic";

export default async function HomePage() {
  const requestHeaders = await headers();
  const surface = getSurface(requestHeaders);
  if (surface === "unknown") forbidden();
  if (surface === "hub") redirect("/admin/accounts");
  const session = await getCurrentSession();
  if (!session) redirect("/login");

  const projects = await prisma.userProjectGrant.findMany({
    where: { userId: session.user.id, revokedAt: null, connection: { enabled: true } },
    orderBy: { connection: { name: "asc" } },
    select: { connection: { select: { name: true, description: true, origin: true } } }
  });
  const csrf = createCsrfToken();

  return (
    <main className="admin-main">
      <a className="skip-link" href="#main-content">Ir para o conteúdo</a>
      <header className="page-header">
        <div><p className="eyebrow">BielOS</p><h1>Projetos</h1></div>
        <div><a className="text-link" href="/account/security">Minha conta</a>
          <form action="/api/logout" method="post"><input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrf} /><button type="submit">Sair</button></form>
        </div>
      </header>
      <section id="main-content" className="project-list" aria-label="Projetos autorizados">
        {projects.length ? projects.map(({ connection }) => (
          <a className="project-link" href={connection.origin} key={connection.origin}>
            <span className="row-main"><strong>{connection.name}</strong>{connection.description ? <span>{connection.description}</span> : null}</span>
            <span>Acessar</span>
          </a>
        )) : <p className="muted">Nenhum projeto disponível.</p>}
      </section>
    </main>
  );
}
