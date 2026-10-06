import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";
import { getCurrentSession } from "../../lib/auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../lib/cloudflare-access";
import { getSurface, safeReturnTo } from "../../lib/surface";
import { PasswordField } from "../password-field";

export const dynamic = "force-dynamic";

export default async function LoginPage({ searchParams }: { searchParams?: Promise<{ error?: string; reauth?: string; recovered?: string; returnTo?: string }> }) {
  const requestHeaders = await headers();
  const surface = getSurface(requestHeaders);
  if (surface === "unknown") forbidden();
  if (surface === "hub" && !isCloudflareAccessAllowed(await validateHubCloudflareAccess(requestHeaders, "admin-login-page"))) forbidden();
  const session = await getCurrentSession();
  const params = await searchParams;
  const reauth = params?.reauth === "1";
  if (session && ((surface === "hub" && session.user.role !== "ADMIN") || (surface === "portal" && session.user.role !== "USER"))) forbidden();
  const returnTo = safeReturnTo(params?.returnTo, surface, session?.user.role);
  if (session && !reauth) redirect(returnTo ?? (session.user.role === "ADMIN" ? "/admin/accounts" : "/"));
  const csrfToken = createCsrfToken({ scope: "login" });

  return (
    <main className="auth-page">
      <section className="auth-panel" aria-labelledby="login-title">
        <p className="eyebrow">BielOS</p>
        <h1 id="login-title">{reauth ? "Confirmar identidade" : "Entrar"}</h1>
        {reauth ? <p>Entre novamente para continuar com a confirmação de segurança solicitada pelo projeto.</p> : null}
        {params?.recovered ? <p className="form-success" role="status">A senha foi atualizada. Entre com sua nova senha.</p> : null}
        <form className="form-stack" action="/api/login" method="post">
          <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
          <input type="hidden" name="returnTo" value={returnTo ?? ""} />
          {reauth ? <input type="hidden" name="reauth" value="1" /> : null}
          <label>E-mail<input type="email" name="email" autoComplete="username" maxLength={320} required /></label>
          <div className="password-control">
            <label htmlFor="login-password">Senha</label>
            <PasswordField id="login-password" name="password" autoComplete="current-password" maxLength={256} required />
          </div>
          {params?.error ? <p className="form-error" role="alert">E-mail ou senha inválidos.</p> : null}
          <button className="button-primary" type="submit">Entrar</button>
        </form>
        <a className="subtle-link" href="/recover">Recuperar conta</a>
      </section>
    </main>
  );
}
