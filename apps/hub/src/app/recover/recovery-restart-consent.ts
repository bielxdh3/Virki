// Next/React may encode a nested FormData Server Action argument with the
// bounded _<argument>_ prefix. This is strictly a same-origin/CSRF-checked
// abandonment acknowledgement, never a recovery authorization proof.
export function hasRecoveryRestartConsent(formData: FormData): boolean {
  const confirmed = [...formData.entries()].filter(([key]) =>
    key === "confirmRecoveryRestart" || /^_\d+_confirmRecoveryRestart$/u.test(key));
  // Do not let duplicate or conflicting values change interpretation.
  return confirmed.length === 1 && confirmed[0]?.[1] === "yes";
}
