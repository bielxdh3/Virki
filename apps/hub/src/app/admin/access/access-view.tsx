import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@virki/auth/csrf";
import { prisma } from "@virki/database";
import { grantProjectAccessAction, revokeProjectAccessAction } from "../actions";

// Callers must run requireAdminPage() first; see ./page.tsx.
export async function AccessView({ searchParams }: { searchParams: Promise<{ status?: string; error?: string }> }) {
  const params = await searchParams;
  const [users, connections, grants, csrf] = await Promise.all([
    prisma.user.findMany({ where: { role: "USER", isActive: true, accountStatus: "ACTIVE" }, select: { id: true, email: true, displayName: true }, orderBy: { email: "asc" } }),
    prisma.projectConnection.findMany({ where: { enabled: true }, select: { id: true, name: true, origin: true }, orderBy: { name: "asc" } }),
    prisma.userProjectGrant.findMany({ where: { revokedAt: null }, select: { id: true, createdAt: true, user: { select: { email: true, displayName: true, role: true } }, connection: { select: { name: true, enabled: true } } }, orderBy: [{ createdAt: "desc" }, { id: "desc" }], take: 200 }),
    Promise.resolve(createCsrfToken({ scope: "admin-access" }))
  ]);

  return <main className="admin-main" id="admin-content" tabIndex={-1}>
    <header className="page-header"><div><p className="eyebrow">Administração</p><h1>Acessos</h1><p>Autorize somente a entrada de contas ativas em conexões habilitadas.</p></div></header>
    {params.status && <p className="form-success" role="status">Alteração concluída.</p>}
    {params.error && <p className="form-error" role="alert">A ação não foi concluída. Confira a seleção e a elevação de segurança.</p>}
    <section className="surface"><h2>Conceder acesso</h2>
      {users.length === 0 || connections.length === 0 ? <p className="muted">Cadastre um usuário ativo e habilite uma conexão antes de conceder acesso.</p> : <form action={grantProjectAccessAction} className="form-stack">
        <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrf} />
        <label>Conta<select name="userId" required defaultValue=""><option value="" disabled>Escolha uma conta</option>{users.map((user) => <option key={user.id} value={user.id}>{user.displayName ? `${user.displayName} · ${user.email}` : user.email}</option>)}</select></label>
        <label>Projeto<select name="connectionId" required defaultValue=""><option value="" disabled>Escolha um projeto</option>{connections.map((connection) => <option key={connection.id} value={connection.id}>{connection.name} · {connection.origin}</option>)}</select></label>
        <button className="button-primary" type="submit">Conceder acesso</button>
      </form>}
    </section>
    <section className="surface"><h2>Concessões não revogadas ({grants.length}{grants.length === 200 ? "+" : ""})</h2>
      {grants.length === 0 ? <p className="muted">Nenhuma concessão registrada.</p> : <div className="row-list">{grants.map((grant) => <article className="list-row" key={grant.id}>
        <div className="row-main"><strong>{grant.user.displayName || grant.user.email} → {grant.connection.name}</strong><span>{grant.user.email}{grant.connection.enabled ? "" : " · conexão desabilitada"}</span>
          {grant.user.role === "ADMIN" && <span className="muted">Conta ADMIN · concessão legada; não autoriza entrada no projeto.</span>}
        </div>
        <form action={revokeProjectAccessAction}><input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrf} /><input type="hidden" name="grantId" value={grant.id} /><button className="button-danger" type="submit">Revogar</button></form>
      </article>)}</div>}
    </section>
  </main>;
}
