import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import { cookies, headers } from "next/headers";
import { forbidden } from "next/navigation";
import { getAccountRecoveryState } from "@bielos/auth/security";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../lib/cloudflare-access";
import { getSurface } from "../../lib/surface";
import { RECOVERY_COOKIE_NAME } from "../../lib/recovery";
import { completeRecoveryAction, openRecoveryAction, requestAdministrativeRecoveryAction, requestRecoveryAction } from "./actions";
import { RecoveryVerificationForm } from "./recovery-verification-form";

export const dynamic = "force-dynamic";

export default async function RecoverPage({ searchParams }: { searchParams?: Promise<{ request?: string; requestId?: string; sent?: string; verified?: string; error?: string }> }) {
  const requestHeaders = await headers();
  const surface = getSurface(requestHeaders);
  if (surface !== "portal" && surface !== "hub" && !(surface === "local" && process.env.NODE_ENV !== "production")) forbidden();
  if (surface === "hub" && !isCloudflareAccessAllowed(await validateHubCloudflareAccess(requestHeaders, "account-recovery-page"))) forbidden();
  const expectedRole = surface === "hub" ? "ADMIN" : "USER";
  const params = await searchParams;
  const cookieStore = await cookies();
  const requestKey = cookieStore.get(RECOVERY_COOKIE_NAME)?.value;
  const state = params?.requestId && requestKey ? await getAccountRecoveryState(params.requestId, requestKey, new Date(), expectedRole) : null;
  const csrf = {
    request: createCsrfToken({ scope: "recovery-request" }),
    adminRequest: createCsrfToken({ scope: "recovery-admin-request" }),
    open: createCsrfToken({ scope: "recovery-open" }),
    verify: createCsrfToken({ scope: "recovery-verify" }),
    complete: createCsrfToken({ scope: "recovery-complete" })
  };
  const legacyRequestKey = params?.request ?? "";
  const recoveryErrorMessage = params?.error && (!params.requestId || state)
    ? state?.status === "PENDING" && !state.emailVerified
      ? "Não foi possível validar o código. Confira o código enviado ou solicite novas instruções."
      : params.requestId
        ? "Não foi possível concluir esta etapa. O link pode ter expirado; tente novamente ou solicite novas instruções."
        : "Não foi possível abrir este link. Solicite novas instruções pelo formulário abaixo."
    : null;

  return (
    <main className="auth-page">
      <section className="auth-panel" aria-labelledby="recover-title">
        <p className="eyebrow">BielOS</p>
        <h1 id="recover-title">{expectedRole === "ADMIN" ? "Recuperar acesso administrativo" : "Recuperar conta"}</h1>
        {legacyRequestKey ? <>
          <p>Este link precisa ser aberto em uma etapa segura antes de continuar.</p>
          <form className="form-stack" action={openRecoveryAction}>
            <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrf.open} />
            <input type="hidden" name="requestKey" value={legacyRequestKey} />
            <button className="button-primary" type="submit">Continuar recuperação</button>
          </form>
        </> : null}

        {!legacyRequestKey && !params?.requestId ? <>
          <p>Se houver uma conta ativa com esse endereço, as instruções serão enviadas por e-mail.</p>
          <form className="form-stack" action={expectedRole === "ADMIN" ? requestAdministrativeRecoveryAction : requestRecoveryAction}>
            <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={expectedRole === "ADMIN" ? csrf.adminRequest : csrf.request} />
            <label>E-mail<input type="email" name="email" autoComplete="email" maxLength={320} required /></label>
            <button className="button-primary" type="submit">Enviar instruções</button>
          </form>
          {params?.sent ? <p role="status">Se a conta puder ser recuperada, você receberá instruções no e-mail cadastrado.</p> : null}
        </> : null}

        {params?.requestId && !state ? <p className="form-error" role="alert">Este link de recuperação não é válido ou expirou. <a href="/recover">Solicite novas instruções.</a></p> : null}
        {state?.status === "PENDING" && !state.emailVerified ? <>
          <p>Informe o código enviado ao endereço cadastrado. Depois, um administrador analisará a solicitação.</p>
          <RecoveryVerificationForm csrf={csrf.verify} csrfFieldName={CSRF_FORM_FIELD_NAME} requestId={state.id} />
        </> : null}
        {state?.status === "PENDING" && state.emailVerified ? <p role="status">E-mail confirmado. Aguarde a análise administrativa; esta página será liberada para definir uma nova senha após a aprovação.</p> : null}
        {state?.status === "APPROVED" ? <>
          <p role="status">Solicitação aprovada. Defina uma nova senha para concluir a recuperação do acesso.</p>
          <form className="form-stack" action={completeRecoveryAction}>
            <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrf.complete} />
            <input type="hidden" name="requestId" value={state.id} />
            <label>Nova senha<input type="password" name="newPassword" minLength={12} maxLength={256} autoComplete="new-password" required /></label>
            <button className="button-primary" type="submit">Concluir recuperação</button>
          </form>
        </> : null}
        {recoveryErrorMessage ? <p className="form-error" role="alert">{recoveryErrorMessage}</p> : null}
        <a className="subtle-link" href="/login">Voltar ao login</a>
      </section>
    </main>
  );
}
