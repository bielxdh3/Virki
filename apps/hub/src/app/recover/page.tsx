import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import { headers } from "next/headers";
import { forbidden } from "next/navigation";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../lib/cloudflare-access";
import { getSurface } from "../../lib/surface";
import { completeRecoveryAction, requestRecoveryAction, verifyRecoveryAction } from "./actions";

export const dynamic = "force-dynamic";

export default async function RecoverPage({ searchParams }: { searchParams?: Promise<{ request?: string; sent?: string; verified?: string; error?: string }> }) {
  const requestHeaders = await headers();
  const surface = getSurface(requestHeaders);
  if (surface === "unknown" || (surface === "hub" && !isCloudflareAccessAllowed(await validateHubCloudflareAccess(requestHeaders, "account-recovery-page")))) forbidden();
  const params = await searchParams;
  const csrf = createCsrfToken();
  const requestKey = params?.request ?? "";
  return (
    <main className="auth-page">
      <section className="auth-panel" aria-labelledby="recover-title">
        <p className="eyebrow">BielOS</p>
        <h1 id="recover-title">Recuperar conta</h1>
        <p>Se houver uma conta elegível, as instruções serão enviadas ao e-mail verificado.</p>
        <form className="form-stack" action={requestRecoveryAction}>
          <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrf} />
          <label>E-mail<input type="email" name="email" autoComplete="email" required /></label>
          <button className="button-secondary" type="submit">Enviar instruções</button>
        </form>
        {params?.sent ? <p role="status">Verifique seu e-mail.</p> : null}
        {requestKey ? <>
          <form className="form-stack" action={verifyRecoveryAction}>
            <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrf} />
            <input type="hidden" name="requestKey" value={requestKey} />
            <label>Código<input name="code" inputMode="numeric" pattern="[0-9]{6}" required /></label>
            <button className="button-secondary" type="submit">Verificar e-mail</button>
          </form>
          <p>A recuperação exige aprovação administrativa.</p>
          <form className="form-stack" action={completeRecoveryAction}>
            <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrf} />
            <input type="hidden" name="requestKey" value={requestKey} />
            <label>Nova senha<input type="password" name="newPassword" minLength={12} autoComplete="new-password" required /></label>
            <button className="button-primary" type="submit">Concluir recuperação</button>
          </form>
        </> : null}
        {params?.error ? <p className="form-error" role="alert">Não foi possível concluir esta etapa.</p> : null}
        <a className="subtle-link" href="/login">Voltar ao login</a>
      </section>
    </main>
  );
}
