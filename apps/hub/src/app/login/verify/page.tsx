import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";
import { getCurrentSession } from "../../../lib/auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../lib/cloudflare-access";
import { getSurface, safeReturnTo } from "../../../lib/surface";

export const dynamic = "force-dynamic";

export default async function LoginVerificationPage({ searchParams }: { searchParams?: Promise<{ ceremony?: string; factor?: string; error?: string; returnTo?: string }> }) {
  const requestHeaders = await headers();
  const surface = getSurface(requestHeaders);
  if (surface === "unknown") forbidden();
  if (surface === "hub" && !isCloudflareAccessAllowed(await validateHubCloudflareAccess(requestHeaders, "admin-login-verification-page"))) forbidden();
  if (await getCurrentSession()) redirect(safeReturnTo((await searchParams)?.returnTo) ?? "/");
  const params = await searchParams;
  const ceremony = params?.ceremony ?? "";
  const factor = params?.factor === "totp" ? "totp" : "email";
  const returnTo = safeReturnTo(params?.returnTo) ?? "";
  const csrfToken = createCsrfToken();

  return (
    <main className="auth-page">
      <section className="auth-panel" aria-labelledby="verify-title">
        <p className="eyebrow">BielOS</p>
        <h1 id="verify-title">Verificação de segurança</h1>
        <p>{factor === "totp" ? "Informe o código do aplicativo autenticador." : "Informe o código enviado ao e-mail da conta."}</p>
        <form className="form-stack" action="/api/login/verify" method="post">
          <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
          <input type="hidden" name="ceremony" value={ceremony} />
          <input type="hidden" name="factor" value={factor} />
          <input type="hidden" name="returnTo" value={returnTo} />
          <label>Código<input name="code" inputMode="numeric" pattern="[0-9]{6}" autoComplete="one-time-code" required /></label>
          {params?.error ? <p className="form-error" role="alert">Não foi possível validar este código.</p> : null}
          <button className="button-primary" type="submit">Continuar</button>
        </form>
      </section>
    </main>
  );
}
