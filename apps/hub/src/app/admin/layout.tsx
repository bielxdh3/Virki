import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import { headers } from "next/headers";
import { getSurface, trustedReturnTo } from "../../lib/surface";
import { requireAdminPage } from "../../lib/admin-page";

const navigation = [
  ["/admin/accounts", "Contas"],
  ["/admin/access", "Acessos"],
  ["/admin/security", "Segurança"],
  ["/admin/audit", "Auditoria"],
  ["/admin/connections", "Conexões"]
] as const;

export const dynamic = "force-dynamic";

export default async function AdminLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  const session = await requireAdminPage();
  const requestHeaders = await headers();
  const surface = getSurface(requestHeaders);
  const csrf = createCsrfToken();
  const currentPath = trustedReturnTo(requestHeaders, surface, session.user.role);
  const currentPathname = currentPath?.split("?", 1)[0];

  return (
    <div className="admin-shell">
      <a className="skip-link" href="#admin-content">Ir para o conteúdo</a>
      <aside className="admin-sidebar">
        <a className="brand" href="/admin/accounts">BielOS · Admin</a>
        <nav className="admin-nav" aria-label="Admin">
          {navigation.map(([href, label]) => <a href={href} key={href} aria-current={currentPathname === href || currentPathname?.startsWith(`${href}/`) ? "page" : undefined}>{label}</a>)}
        </nav>
        <form action="/api/logout" method="post">
          <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrf} />
          <button type="submit">Sair</button>
        </form>
      </aside>
      {children}
    </div>
  );
}
