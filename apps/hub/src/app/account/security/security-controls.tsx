"use client";

import { useActionState } from "react";
import { confirmTotpAction, disableTotpAction, regenerateRecoveryCodesAction, startTotpAction, type AccountSecurityState } from "./actions";

const initial: AccountSecurityState = { status: "idle" };

export function TotpControls({ csrf, active, pending }: { csrf: string; active: boolean; pending: boolean }) {
  const [enrollment, startAction, starting] = useActionState(startTotpAction, initial);
  const [confirmation, confirmAction, confirming] = useActionState(confirmTotpAction, initial);
  const [regenerated, regenerateAction, regenerating] = useActionState(regenerateRecoveryCodesAction, initial);
  return <section className="surface"><h2>Autenticação multifator</h2><p>{active ? "Aplicativo autenticador (TOTP) ativo." : pending ? "Configuração iniciada. Confirme o código do aplicativo." : "TOTP não está ativo. A verificação por e-mail continua disponível."}</p>
    {!active && !enrollment.secret && <form action={startAction} className="form-stack"><input type="hidden" name="csrfToken" value={csrf} /><label>Senha atual<input name="password" type="password" autoComplete="current-password" required /></label><button type="submit" disabled={starting}>{starting ? "Iniciando…" : "Configurar aplicativo autenticador"}</button>{enrollment.status === "error" && <p className="form-error" role="alert">Não foi possível iniciar. A configuração não substitui um TOTP ativo.</p>}</form>}
    {enrollment.secret && <form action={confirmAction} className="form-stack"><input type="hidden" name="csrfToken" value={csrf} /><p>Adicione esta chave no aplicativo autenticador:</p><p><code>{enrollment.secret}</code></p><label>Código atual do aplicativo<input name="code" inputMode="numeric" autoComplete="one-time-code" minLength={6} maxLength={6} required /></label><button type="submit" disabled={confirming}>{confirming ? "Confirmando…" : "Ativar TOTP"}</button>{confirmation.status === "error" && <p className="form-error" role="alert">Código inválido ou configuração expirada.</p>}{confirmation.recoveryCodes && <RecoveryCodes codes={confirmation.recoveryCodes} />}</form>}
    {active && <><form action={regenerateAction} className="form-stack"><input type="hidden" name="csrfToken" value={csrf} /><label>Confirme com TOTP para substituir códigos de recuperação<input name="code" inputMode="numeric" autoComplete="one-time-code" minLength={6} maxLength={6} required /></label><button type="submit" disabled={regenerating}>{regenerating ? "Gerando…" : "Gerar novos códigos"}</button>{regenerated.status === "error" && <p className="form-error" role="alert">Código inválido ou já usado. Tente com o código atual.</p>}{regenerated.recoveryCodes && <RecoveryCodes codes={regenerated.recoveryCodes} />}</form><form action={disableTotpAction} className="form-stack"><input type="hidden" name="csrfToken" value={csrf} /><label>Confirme com TOTP para desativar e encerrar todas as sessões<input name="code" inputMode="numeric" autoComplete="one-time-code" minLength={6} maxLength={6} required /></label><button className="button-danger" type="submit">Desativar TOTP</button></form></>}
  </section>;
}

function RecoveryCodes({ codes }: { codes: string[] }) {
  return <section className="surface form-success" aria-live="polite"><h3>Códigos de recuperação — exibidos uma vez</h3><p>Guarde-os fora deste dispositivo. Os códigos anteriores foram invalidados.</p><ul>{codes.map((code) => <li key={code}><code>{code}</code></li>)}</ul></section>;
}
