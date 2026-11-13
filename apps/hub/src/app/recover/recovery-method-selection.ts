export type RecoveryProof = "EMAIL" | "TOTP" | "PASSKEY";
export type RecoveryRequestMethod =
  | "PASSKEY_TOTP"
  | "PASSKEY_EMAIL"
  | "TOTP_EMAIL"
  | "PASSKEY_ADMIN"
  | "TOTP_ADMIN"
  | "EMAIL_ADMIN";

type RecoveryPolicy = { proofs: RecoveryProof[]; adminReview: boolean };

const POLICIES: Record<RecoveryRequestMethod, RecoveryPolicy> = {
  PASSKEY_EMAIL: { proofs: ["PASSKEY", "EMAIL"], adminReview: false },
  TOTP_EMAIL: { proofs: ["TOTP", "EMAIL"], adminReview: false },
  PASSKEY_TOTP: { proofs: ["PASSKEY", "TOTP"], adminReview: false },
  PASSKEY_ADMIN: { proofs: ["PASSKEY"], adminReview: true },
  TOTP_ADMIN: { proofs: ["TOTP"], adminReview: true },
  EMAIL_ADMIN: { proofs: ["EMAIL"], adminReview: true }
};

export function recoveryPolicyFromMethod(value: unknown): RecoveryPolicy | null {
  if (typeof value !== "string" || !Object.hasOwn(POLICIES, value)) return null;
  const policy = POLICIES[value as RecoveryRequestMethod];
  return { proofs: [...policy.proofs], adminReview: policy.adminReview };
}

// Reverse only the six public, fixed method policies; never trust a caller's
// potentially corrupted intent cookie as the source of this mapping.
export function recoveryMethodFromPolicy(value: RecoveryPolicy): RecoveryRequestMethod | null {
  return (Object.keys(POLICIES) as RecoveryRequestMethod[]).find(method =>
    POLICIES[method].adminReview === value.adminReview &&
    POLICIES[method].proofs.length === value.proofs.length &&
    POLICIES[method].proofs.every(proof => value.proofs.includes(proof))
  ) ?? null;
}
