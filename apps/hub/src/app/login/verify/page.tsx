import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@virki/auth/csrf";
import { DEVICE_COOKIE_NAME, getLoginBackupOption, getLoginChallengeFactor } from "@virki/auth/security";
import { cookies } from "next/headers";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";
import { getCurrentSession } from "../../../lib/auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../lib/cloudflare-access";
import { getSurface, safeReturnTo } from "../../../lib/surface";
import { displayedLoginFactor } from "../../../lib/login-verification-factor";

export const dynamic = "force-dynamic";

export default async function LoginVerificationPage({ searchParams }: { searchParams?: Promise<{ ceremony?: string; factor?: string; flow?: string; error?: string; reauth?: string; returnTo?: string }> }) {
  const requestHeaders = await headers();
  const surface = getSurface(requestHeaders);
  if (surface === "unknown") forbidden();
  if (surface === "hub" && !isCloudflareAccessAllowed(await validateHubCloudflareAccess(requestHeaders, "admin-login-verification-page"))) forbidden();
  const params = await searchParams;
  const session = await getCurrentSession();
  if (session && ((surface === "hub" && session.user.role !== "ADMIN") || (surface === "portal" && session.user.role !== "USER"))) forbidden();
  const ceremony = params?.ceremony ?? "";
  const requestedFactor = params?.factor === "totp" || params?.factor === "recovery" || params?.factor === "backup" ? params.factor : "email";
  const returnTo = safeReturnTo(params?.returnTo, surface) ?? "";
  const reauth = params?.reauth === "1";
  const loginParams = new URLSearchParams();
  if (returnTo) loginParams.set("returnTo", returnTo);
  if (reauth) loginParams.set("reauth", "1");
  const loginHref = loginParams.size ? `/login?${loginParams.toString()}` : "/login";
  if (session && !ceremony && !reauth) redirect(safeReturnTo(params?.returnTo, surface, session.user.role) ?? (session.user.role === "ADMIN" ? "/admin/accounts" : "/"));
  if (!ceremony) redirect(loginHref);
  const csrfToken = createCsrfToken({ scope: "login-verification" });
  const factorSelectionCsrf = createCsrfToken({ scope: "login-factor-selection" });
  const deviceToken = (await cookies()).get(DEVICE_COOKIE_NAME)?.value ?? "";
  const requiredRole = surface === "hub" ? "ADMIN" : surface === "portal" ? "USER" : undefined;
  const serverFactor = await getLoginChallengeFactor(ceremony, deviceToken, requiredRole);
  const factor = displayedLoginFactor(serverFactor, requestedFactor);
  if (!factor) redirect(loginHref);
  const backupAvailable = factor === "totp" && await getLoginBackupOption(ceremony, deviceToken, requiredRole);
  const recoveryParams = new URLSearchParams({ ceremony, factor: "recovery", flow: "recovery" });
  if (returnTo) recoveryParams.set("returnTo", returnTo);
  if (reauth) recoveryParams.set("reauth", "1");

  return (
    <main className="auth-page">
      <section className="auth-panel" aria-labelledby="verify-title">
        <p className="eyebrow">Virki</p>
        <h1 id="verify-title">Verificação de segurança</h1>
        <p>{factor === "totp" ? "Informe o código do aplicativo autenticador." : factor === "backup" ? "Informe um código reserva ainda não utilizado. Seu autenticador continuará ativo." : factor === "recovery" ? "Use um código de recuperação de uso único. Depois, será necessário configurar o autenticador novamente." : "Informe o código enviado ao e-mail da conta."}</p>
        <form className="form-stack" action="/api/login/verify" method="post">
          <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
          <input type="hidden" name="ceremony" value={ceremony} />
          <input type="hidden" name="factor" value={factor} />
          {params?.flow === "recovery" ? <input type="hidden" name="flow" value="recovery" /> : null}
          <input type="hidden" name="returnTo" value={returnTo} />
          {reauth ? <input type="hidden" name="reauth" value="1" /> : null}
          <label>Código<input name="code" inputMode={factor === "recovery" || factor === "backup" ? "text" : "numeric"} pattern={factor === "recovery" || factor === "backup" ? "[A-Fa-f0-9 -]{18,32}" : "[0-9]{6}"} autoComplete="one-time-code" maxLength={factor === "recovery" || factor === "backup" ? 32 : 6} required /></label>
          {params?.error ? <p className="form-error" role="alert">Não foi possível validar este código.</p> : null}
          <button className="button-primary" type="submit">Continuar</button>
        </form>
        {backupAvailable ? <form className="form-stack" action="/api/login/factor" method="post">
          <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={factorSelectionCsrf} />
          <input type="hidden" name="ceremony" value={ceremony} />
          <input type="hidden" name="returnTo" value={returnTo} />
          {reauth ? <input type="hidden" name="reauth" value="1" /> : null}
          <button type="submit" className="button-secondary">Entrar com um código reserva</button>
        </form> : null}
        <nav className="auth-link-list" aria-label="Opções de autenticação">
          {factor === "totp" ? <a className="subtle-link" href={`/login/verify?${recoveryParams.toString()}`}>Perdi o autenticador? Recuperar TOTP (desativa o autenticador)</a> : null}
          <a className="subtle-link" href={loginHref}>Voltar ao login</a>
        </nav>
      </section>
    </main>
  );
}
