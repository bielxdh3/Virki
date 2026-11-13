import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@virki/auth/csrf";
import { cookies, headers } from "next/headers";
import { forbidden } from "next/navigation";
import { getAccountRecoveryRequestId, getAccountRecoveryState } from "@virki/auth/security";
import { getMultiMethodRecoveryState, hasIndependentAdministratorForRole, restoreProvenMultiMethodRecoveryBrowser } from "@virki/auth/recovery-methods";
import { passkeysEnabledForRequest } from "@virki/auth/passkeys";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../lib/cloudflare-access";
import { getSurface, requestHost } from "../../lib/surface";
import { RECOVERY_COOKIE_NAME } from "../../lib/recovery";
import {
  openRecoveryAction, requestAdministrativeRecoveryAction, requestRecoveryAction,
  startSelectedRecoveryPasskeyAction, verifySelectedRecoveryEmailAction, verifySelectedRecoveryPasskeyAction,
  verifySelectedRecoveryTotpAction
} from "./actions";
import { RecoveryCompletionForm } from "./recovery-completion-form";
import { RecoveryNewMailStage } from "./recovery-new-mail-stage";
import { RecoveryProofStage, type RecoveryProof } from "./recovery-proof-stage";
import { RecoveryRequestForm, type RecoveryRequestMethod } from "./recovery-request-form";
import { RecoveryVerificationForm } from "./recovery-verification-form";
import { RecoverySwitchForm } from "./recovery-switch-form";
import { parseRecoveryIntent, RECOVERY_BROWSER_COOKIE, RECOVERY_CANDIDATE_COOKIE, RECOVERY_INTENT_COOKIE } from "./recovery-cookie";
import { recoveryPolicyFromMethod } from "./recovery-method-selection";

export const dynamic = "force-dynamic";

export default async function RecoverPage({ searchParams }: { searchParams?: Promise<{ request?: string; requestId?: string; sent?: string; verified?: string; error?: string; switch?: string }> }) {
  const requestHeaders = await headers();
  const surface = getSurface(requestHeaders);
  if (surface !== "portal" && surface !== "hub" && !(surface === "local" && process.env.NODE_ENV !== "production")) forbidden();
  if (surface === "hub" && !isCloudflareAccessAllowed(await validateHubCloudflareAccess(requestHeaders, "account-recovery-page"))) forbidden();
  const expectedRole = surface === "hub" ? "ADMIN" : "USER";
  const params = await searchParams;
  const cookieStore = await cookies();
  const requestKey = cookieStore.get(RECOVERY_COOKIE_NAME)?.value;
  const browserToken = cookieStore.get(RECOVERY_BROWSER_COOKIE)?.value;
  const recoveryIntent = parseRecoveryIntent(cookieStore.get(RECOVERY_INTENT_COOKIE)?.value);
  // A proven browser-bound recovery must survive a missing, malformed, foreign,
  // or wrong-method UI hint. The backend independently validates BOTH bearer
  // secrets, the owner, live proof, role and expiry before identifying a request.
  const proven = params?.requestId && requestKey && browserToken
    ? await restoreProvenMultiMethodRecoveryBrowser(requestKey, browserToken, expectedRole).catch(() => null)
    : null;
  const recoveryPolicy = proven && params?.requestId && proven.requestId === params.requestId ? proven.policy
    : recoveryIntent && params?.requestId && recoveryIntent.requestId === params.requestId
      ? recoveryPolicyFromMethod(recoveryIntent.method) : null;
  const isMultiMethodRequest = Boolean(params?.requestId && requestKey && browserToken && recoveryPolicy);
  // Unknown accounts receive the same pre-proof screen as legitimate requests.
  // Never fall back to the legacy "invalid link" branch for synthetic requests.
  const multiState = params?.requestId && requestKey && browserToken && recoveryPolicy
    ? await getMultiMethodRecoveryState(params.requestId, requestKey, browserToken, expectedRole, recoveryPolicy).catch(() => ({
        status: "PENDING" as const, proofs: recoveryPolicy.proofs, adminReview: recoveryPolicy.adminReview,
        emailVerified: false, passkeyVerified: false, totpVerified: false,
        newMailboxRequired: !recoveryPolicy.proofs.includes("EMAIL"), newMailboxChallengeSent: false, newMailboxVerified: false
      }))
    : null;
  const state = !isMultiMethodRequest && params?.requestId && requestKey
    ? await getAccountRecoveryState(params.requestId, requestKey, new Date(), expectedRole)
    : null;
  const hasOtherActiveAdmin = !params?.requestId && !params?.request
    ? await hasIndependentAdministratorForRole(expectedRole).catch(() => false)
    : false;
  // Method availability is global, never account-specific, to prevent enrollment enumeration.
  // ADMIN credentials are enrolled separately under the hub relying party.
  const passkeysAvailable = passkeysEnabledForRequest(surface, requestHost(requestHeaders), process.env, expectedRole);
  const availableMethods: RecoveryRequestMethod[] = expectedRole === "USER"
    ? ["TOTP_EMAIL",
      ...(passkeysAvailable ? ["PASSKEY_EMAIL", "PASSKEY_TOTP"] as const : []),
      ...(hasOtherActiveAdmin ? ["TOTP_ADMIN", "EMAIL_ADMIN"] as const : []),
      ...(passkeysAvailable && hasOtherActiveAdmin ? ["PASSKEY_ADMIN"] as const : [])]
    : ["TOTP_EMAIL", ...(passkeysAvailable ? ["PASSKEY_EMAIL", "PASSKEY_TOTP"] as const : []),
      ...(hasOtherActiveAdmin ? ["TOTP_ADMIN", "EMAIL_ADMIN"] as const : []),
      ...(passkeysAvailable && hasOtherActiveAdmin ? ["PASSKEY_ADMIN"] as const : [])];
  const candidateKey = cookieStore.get(RECOVERY_CANDIDATE_COOKIE)?.value;
  const candidate = params?.switch === "1" && params.requestId && candidateKey
    ? await getAccountRecoveryRequestId(candidateKey, new Date(), expectedRole)
    : null;
  const confirmRecoverySwitch = Boolean(candidate && params?.requestId && candidate.id === params.requestId);
  const csrf = {
    request: createCsrfToken({ scope: "recovery-request" }),
    adminRequest: createCsrfToken({ scope: "recovery-admin-request" }),
    open: createCsrfToken({ scope: "recovery-open" }),
    verify: createCsrfToken({ scope: "recovery-verify" }),
    complete: createCsrfToken({ scope: "recovery-complete" })
  };
  const legacyRequestKey = params?.request ?? "";
  const recoveryErrorMessage = params?.error === "password" && (state?.status === "APPROVED" || multiState?.status === "APPROVED")
    ? state?.purpose === "INVITATION"
      ? "Escolha uma senha de pelo menos 12 caracteres, sem caracteres de controle."
      : expectedRole === "ADMIN"
        ? "A senha administrativa deve ter pelo menos 16 caracteres, sem caracteres de controle."
        : "A senha deve ter pelo menos 12 caracteres, sem caracteres de controle."
    : params?.error && (!params.requestId || state || multiState)
    ? state?.status === "PENDING" && !state.emailVerified
      ? "Não foi possível validar o código. Confira o código enviado ou solicite novas instruções."
      : params.requestId
        ? "Não foi possível concluir esta etapa. O link pode ter expirado; tente novamente ou solicite novas instruções."
        : "Não foi possível abrir este link. Solicite novas instruções pelo formulário abaixo."
    : null;

  return (
    <main className="auth-page">
      <section className="auth-panel" aria-labelledby="recover-title">
        <p className="eyebrow">Virki</p>
        <h1 id="recover-title">{state?.purpose === "INVITATION" ? "Ativar sua conta" : expectedRole === "ADMIN" ? "Recuperar acesso administrativo" : "Recuperar conta"}</h1>
        {legacyRequestKey ? <>
          <p>Este link precisa ser aberto em uma etapa segura antes de continuar.</p>
          <form className="form-stack" action={openRecoveryAction}>
            <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrf.open} />
            <input type="hidden" name="requestKey" value={legacyRequestKey} />
            <button className="button-primary" type="submit">Continuar recuperação</button>
          </form>
        </> : null}

        {!legacyRequestKey && !params?.requestId ? <>
          <p>Se sua conta estiver apta à recuperação, confirme os fatores selecionados para definir uma nova senha.</p>
          <RecoveryRequestForm action={expectedRole === "ADMIN" ? requestAdministrativeRecoveryAction : requestRecoveryAction}
            csrf={expectedRole === "ADMIN" ? csrf.adminRequest : csrf.request} csrfFieldName={CSRF_FORM_FIELD_NAME}
            availableMethods={availableMethods} hasOtherActiveAdmin={hasOtherActiveAdmin} />
          {expectedRole === "ADMIN" ? <details>
            <summary>Recuperação administrativa anterior, por e-mail e aprovação</summary>
            <form className="form-stack" action={requestAdministrativeRecoveryAction}>
              <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrf.adminRequest} />
              <label>E-mail<input type="email" name="email" autoComplete="email" maxLength={320} required /></label>
              <button className="button-primary" type="submit">Enviar instruções</button>
            </form>
          </details> : null}
          {params?.sent ? <p role="status">Se a conta puder ser recuperada, você receberá instruções no e-mail cadastrado.</p> : null}
        </> : null}

        {confirmRecoverySwitch ? <>
          <p role="status">Outro link está aberto nesta sessão. Continuar com este link vai encerrar o progresso atual de recuperação neste navegador.</p>
          <RecoverySwitchForm csrf={csrf.open} csrfFieldName={CSRF_FORM_FIELD_NAME} requestId={candidate!.id} />
        </> : null}
        {params?.requestId && !state && !multiState && !confirmRecoverySwitch ? <p className="form-error" role="alert">Este link de recuperação não é mais válido. Se a sua solicitação já foi aprovada, use o link mais recente enviado por e-mail. Caso contrário, <a href="/recover">solicite novas instruções.</a></p> : null}
        {multiState?.status === "PENDING" && params?.requestId ? <RecoveryProofStage
          csrf={csrf.verify} csrfFieldName={CSRF_FORM_FIELD_NAME} requestId={params.requestId}
          requiredProofs={multiState.proofs as RecoveryProof[]}
          verifiedProofs={[
            ...(multiState.emailVerified ? ["EMAIL" as const] : []),
            ...(multiState.totpVerified ? ["TOTP" as const] : []),
            ...(multiState.passkeyVerified ? ["PASSKEY" as const] : [])
          ]}
          needsAdminReview={multiState.adminReview} adminReviewed={false}
          verifyEmailAction={verifySelectedRecoveryEmailAction}
          verifyTotpAction={verifySelectedRecoveryTotpAction}
          startPasskeyAction={startSelectedRecoveryPasskeyAction}
          verifyPasskeyAction={verifySelectedRecoveryPasskeyAction}
        /> : null}
        {multiState?.status === "APPROVED" && params?.requestId ? <>
          {multiState.newMailboxRequired && !multiState.newMailboxVerified ? <RecoveryNewMailStage
            csrf={csrf.verify} csrfFieldName={CSRF_FORM_FIELD_NAME} requestId={params.requestId}
            challengeSent={multiState.newMailboxChallengeSent} /> : <>
            <p role="status">{multiState.newMailboxRequired ? "Novo e-mail confirmado. " : "Confirmações concluídas. "}Defina uma nova senha para finalizar a recuperação.</p>
            <RecoveryCompletionForm csrf={csrf.complete} csrfFieldName={CSRF_FORM_FIELD_NAME} requestId={params.requestId}
              expectedRole={expectedRole} purpose="RECOVERY" />
          </>}
        </> : null}
        {multiState && multiState.status !== "APPROVED" && multiState.status !== "PENDING" ? <p role="status">
          Esta recuperação expirou. <a href="/recover">Solicite uma nova recuperação.</a>
        </p> : null}
        {state?.status === "PENDING" && !state.emailVerified ? <>
          <p>Informe o código enviado ao endereço cadastrado. Depois, um administrador analisará a solicitação.</p>
          <RecoveryVerificationForm csrf={csrf.verify} csrfFieldName={CSRF_FORM_FIELD_NAME} requestId={state.id} />
        </> : null}
        {state?.status === "PENDING" && state.emailVerified ? <p role="status">E-mail confirmado. Um administrador analisará a solicitação. Após a aprovação, você receberá um novo e-mail com um link para definir a senha; abra esse novo link, pois esta página não será atualizada.</p> : null}
        {state?.status === "APPROVED" ? <>
          <p role="status">{state.purpose === "INVITATION" ? "Bem-vindo ao Virki! Defina uma senha para ativar sua conta. O convite é válido por 72 horas e pode ser usado uma vez." : "Defina uma nova senha para concluir o acesso à sua conta."}</p>
          <RecoveryCompletionForm csrf={csrf.complete} csrfFieldName={CSRF_FORM_FIELD_NAME} requestId={state.id} expectedRole={expectedRole} purpose={state.purpose} />
        </> : null}
        {recoveryErrorMessage ? <p className="form-error" role="alert">{recoveryErrorMessage}</p> : null}
        <a className="subtle-link" href="/login">Voltar ao login</a>
      </section>
    </main>
  );
}
