import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";
import { getCurrentSession } from "../../lib/auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../lib/cloudflare-access";
import { getSurface, safeReturnTo } from "../../lib/surface";

export const dynamic = "force-dynamic";

export default async function LoginPage({ searchParams }: { searchParams?: Promise<{ error?: string; returnTo?: string }> }) {
  const requestHeaders = await headers();
  const surface = getSurface(requestHeaders);
  if (surface === "unknown") forbidden();
  if (surface === "hub" && !isCloudflareAccessAllowed(await validateHubCloudflareAccess(requestHeaders, "admin-login-page"))) forbidden();
  const session = await getCurrentSession();
  const params = await searchParams;
  const returnTo = safeReturnTo(params?.returnTo);
  if (session) redirect(returnTo ?? (session.user.role === "ADMIN" ? "/admin/accounts" : "/"));
  const csrfToken = createCsrfToken();

  return (
    <main className="auth-page">
      <section className="auth-panel" aria-labelledby="login-title">
        <p className="eyebrow">BielOS</p>
        <h1 id="login-title">Entrar</h1>
        <form className="form-stack" action="/api/login" method="post">
          <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
          <input type="hidden" name="returnTo" value={returnTo ?? ""} />
          <label>E-mail<input type="email" name="email" autoComplete="username" required /></label>
          <label>Senha<input type="password" name="password" autoComplete="current-password" required /></label>
          {params?.error ? <p className="form-error" role="alert">E-mail ou senha inválidos.</p> : null}
          <button className="button-primary" type="submit">Entrar</button>
        </form>
        <a className="subtle-link" href="/recover">Recuperar conta</a>
      </section>
    </main>
  );
}
