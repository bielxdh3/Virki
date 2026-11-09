import React from "react";

type RecoveryReviewDetailsData = {
  emailVerifiedAt?: Date | string | null;
  recoveryProofs?: readonly string[] | null;
  recoveryAdminReview?: boolean | null;
  recoveryComment?: string | null;
};

const proofLabels: Record<string, string> = {
  EMAIL: "E-mail",
  PASSKEY: "Passkey",
  TOTP: "Aplicativo autenticador"
};

export function recoveryNeedsAdministrativeReview(request: RecoveryReviewDetailsData): boolean {
  // Explicit two/three-factor requests are handled by their own complete-proof path.
  // Empty-policy legacy requests still require the original review.
  return request.recoveryAdminReview !== false;
}

/** Only render this after the enclosing ADMIN route has authenticated the reviewer. */
export function RecoveryReviewDetails({ request }: { request: RecoveryReviewDetailsData }) {
  const proofs = request.recoveryProofs?.filter((value) => Object.hasOwn(proofLabels, value)) ?? [];
  // Legacy requests have no explicit factor policy, and required e-mail proof.
  const summary = proofs.length > 0
    ? proofs.map((value) => proofLabels[value]).join(" + ")
    : request.emailVerifiedAt ? "E-mail verificado (fluxo anterior)" : "Solicitação anterior";
  const comment = typeof request.recoveryComment === "string" ? request.recoveryComment : "";

  return <div className="muted" data-recovery-review-details="true">
    <p>Método solicitado: {summary}{recoveryNeedsAdministrativeReview(request) ? " + aprovação administrativa" : ""}.</p>
    {comment ? <p>Comentário do solicitante: <span className="recovery-review-comment">{comment}</span></p> : null}
  </div>;
}
