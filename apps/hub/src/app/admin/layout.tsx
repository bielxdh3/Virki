import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import { headers } from "next/headers";
import { forbidden } from "next/navigation";
import { getCurrentSession } from "../../lib/auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../lib/cloudflare-access";
import { getSurface } from "../../lib/surface";
import { isAdminRequestAllowed, isAdminRole } from "../../lib/admin-policy";

const navigation = [
  ["/admin/accounts", "Contas"],
  ["/admin/access", "Acessos"],
  ["/admin/security", "Segurança"],
  ["/admin/audit", "Auditoria"],
  ["/admin/connections", "Conexões"]
] as const;

export const dynamic = "force-dynamic";

export default async function AdminLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  const requestHeaders = await headers();
  const accessValid = isCloudflareAccessAllowed(await validateHubCloudflareAccess(requestHeaders, "admin-layout"));
  if (!isAdminRequestAllowed(getSurface(requestHeaders), accessValid)) forbidden();
  const session = await getCurrentSession();
  if (!isAdminRole(session?.user.role)) forbidden();
  const csrf = createCsrfToken();

  return (
    <div className="admin-shell">
      <aside className="admin-sidebar">
        <a className="brand" href="/admin/accounts">BielOS · Admin</a>
        <nav className="admin-nav" aria-label="Admin">
          {navigation.map(([href, label]) => <a href={href} key={href}>{label}</a>)}
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
