import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import { prisma } from "@bielos/database";
import { requireAdminPage } from "../../../lib/admin-page";
import { createAccountAction, setAccountStateAction } from "../actions";

export const dynamic = "force-dynamic";

export default async function AccountsPage({ searchParams }: { searchParams: Promise<{ status?: string; error?: string }> }) {
  await requireAdminPage();
  const params = await searchParams;
  const [users, csrf] = await Promise.all([
    prisma.user.findMany({ where: { role: "USER" }, select: { id: true, email: true, displayName: true, isActive: true, accountStatus: true, secondFactorMethod: true, createdAt: true, _count: { select: { sessions: true, projectGrants: true } } }, orderBy: [{ createdAt: "desc" }, { id: "desc" }], take: 100 }),
    Promise.resolve(createCsrfToken())
  ]);

  return <main className="admin-main">
    <header className="page-header"><div><p className="eyebrow">Administração</p><h1>Contas</h1><p>Provisione e suspenda contas USER. A suspensão encerra todas as sessões.</p></div></header>
    {params.status && <p className="form-success" role="status">Alteração concluída.</p>}
    {params.error && <p className="form-error" role="alert">A ação não foi concluída. Verifique os dados e a elevação de segurança.</p>}
    <section className="surface" aria-labelledby="create-account"><h2 id="create-account">Provisionar conta</h2>
      <form action={createAccountAction} className="form-stack">
        <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrf} />
        <label>Nome<input name="displayName" autoComplete="name" maxLength={80} /></label>
        <label>E-mail<input name="email" type="email" autoComplete="email" required maxLength={254} /></label>
        <label>Senha inicial<input name="password" type="password" autoComplete="new-password" required minLength={12} maxLength={256} /></label>
        <p className="muted">Use uma senha inicial exclusiva e entregue-a ao titular por um canal seguro.</p>
        <button className="button-primary" type="submit">Criar conta</button>
      </form>
    </section>
    <section className="surface"><h2>Usuários ({users.length}{users.length === 100 ? "+" : ""})</h2>
      {users.length === 0 ? <p className="muted">Nenhuma conta USER cadastrada.</p> : <div className="row-list">{users.map((user) => <article className="list-row" key={user.id}>
        <div className="row-main"><strong>{user.displayName || user.email}</strong><span>{user.email} · {user.isActive ? "Ativa" : "Suspensa"} · MFA {user.secondFactorMethod === "TOTP" ? "TOTP" : "e-mail"} · {user._count.projectGrants} acessos</span></div>
        <form action={setAccountStateAction}>
          <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrf} /><input type="hidden" name="userId" value={user.id} /><input type="hidden" name="enabled" value={user.isActive ? "false" : "true"} />
          <button className={user.isActive ? "button-danger" : ""} type="submit">{user.isActive ? "Suspender" : "Reativar"}</button>
        </form>
      </article>)}</div>}
    </section>
  </main>;
}
