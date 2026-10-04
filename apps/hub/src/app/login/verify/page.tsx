import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";
import { getCurrentSession } from "../../../lib/auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../lib/cloudflare-access";
import { getSurface, safeReturnTo } from "../../../lib/surface";

export const dynamic = "force-dynamic";

export default async function LoginVerificationPage({ searchParams }: { searchParams?: Promise<{ ceremony?: string; factor?: string; flow?: string; error?: string; returnTo?: string }> }) {
  const requestHeaders = await headers();
  const surface = getSurface(requestHeaders);
  if (surface === "unknown") forbidden();
  if (surface === "hub" && !isCloudflareAccessAllowed(await validateHubCloudflareAccess(requestHeaders, "admin-login-verification-page"))) forbidden();
  const params = await searchParams;
  const session = await getCurrentSession();
  if (session && ((surface === "hub" && session.user.role !== "ADMIN") || (surface === "portal" && session.user.role !== "USER"))) forbidden();
  const ceremony = params?.ceremony ?? "";
  const factor = params?.factor === "totp" || params?.factor === "recovery" ? params.factor : "email";
  const returnTo = safeReturnTo(params?.returnTo, surface) ?? "";
  const loginHref = returnTo ? `/login?returnTo=${encodeURIComponent(returnTo)}` : "/login";
  if (session && !ceremony) redirect(safeReturnTo(params?.returnTo, surface, session.user.role) ?? (session.user.role === "ADMIN" ? "/admin/accounts" : "/"));
  if (!session && !ceremony) redirect(loginHref);
  const csrfToken = createCsrfToken({ scope: "login-verification" });
  const recoveryParams = new URLSearchParams({ ceremony, factor: "recovery", flow: "recovery" });
  if (returnTo) recoveryParams.set("returnTo", returnTo);

  return (
    <main className="auth-page">
      <section className="auth-panel" aria-labelledby="verify-title">
        <p className="eyebrow">BielOS</p>
        <h1 id="verify-title">Verificação de segurança</h1>
        <p>{factor === "totp" ? "Informe o código do aplicativo autenticador." : factor === "recovery" ? "Use um código de recuperação de uso único. Depois, será necessário configurar o autenticador novamente." : "Informe o código enviado ao e-mail da conta."}</p>
        <form className="form-stack" action="/api/login/verify" method="post">
          <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
          <input type="hidden" name="ceremony" value={ceremony} />
          <input type="hidden" name="factor" value={factor} />
          {params?.flow === "recovery" ? <input type="hidden" name="flow" value="recovery" /> : null}
          <input type="hidden" name="returnTo" value={returnTo} />
          <label>Código<input name="code" inputMode={factor === "recovery" ? "text" : "numeric"} pattern={factor === "recovery" ? "[A-Fa-f0-9 -]{18,24}" : "[0-9]{6}"} autoComplete="one-time-code" maxLength={factor === "recovery" ? 24 : 6} required /></label>
          {params?.error ? <p className="form-error" role="alert">Não foi possível validar este código.</p> : null}
          <button className="button-primary" type="submit">Continuar</button>
        </form>
        <nav className="auth-link-list" aria-label="Opções de autenticação">
          {factor === "totp" ? <a className="subtle-link" href={`/login/verify?${recoveryParams.toString()}`}>Usar um código de recuperação</a> : null}
          <a className="subtle-link" href={loginHref}>Voltar ao login</a>
        </nav>
      </section>
    </main>
  );
}
