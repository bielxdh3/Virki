import { createHash, timingSafeEqual } from "node:crypto";

export const NATIVE_EDGE_PROOF_HEADER = "x-virki-native-edge-proof";
export const MIN_NATIVE_EDGE_SECRET_LENGTH = 32;

export function hasValidNativeEdgeSecretConfig(
  env: Readonly<Record<string, string | undefined>> = process.env
): boolean {
  const edgeProof = env.VIRKI_NATIVE_EDGE_PROOF_SECRET?.trim() ?? "";
  return edgeProof.length >= MIN_NATIVE_EDGE_SECRET_LENGTH;
}

/**
 * Opt-in migration to Virki's native ADMIN authentication perimeter.
 * In production, native mode requires explicit Access opt-out AND a configured
 * high-entropy edge proxy secret; absent/misconfigured values retain Access.
 * This never replaces Virki session, role, CSRF, or elevation checks.
 */
export function isNativeHubPerimeterEnabled(env: Readonly<Record<string, string | undefined>> = process.env): boolean {
  if (env.VIRKI_HUB_PERIMETER_MODE !== "native") return false;
  if (env.NODE_ENV !== "production") return true;
  return env.CLOUDFLARE_ACCESS_JWT_REQUIRED === "false" && hasValidNativeEdgeSecretConfig(env);
}

export function verifyNativeHubEdgeProof(
  headers: Pick<Headers, "get">,
  env: Readonly<Record<string, string | undefined>> = process.env
): boolean {
  const expected = env.VIRKI_NATIVE_EDGE_PROOF_SECRET?.trim() ?? "";
  const provided = headers.get(NATIVE_EDGE_PROOF_HEADER)?.trim() ?? "";
  if (expected.length < MIN_NATIVE_EDGE_SECRET_LENGTH || !provided) return false;
  const expectedDigest = createHash("sha256").update(expected).digest();
  const providedDigest = createHash("sha256").update(provided).digest();
  return timingSafeEqual(expectedDigest, providedDigest);
}
