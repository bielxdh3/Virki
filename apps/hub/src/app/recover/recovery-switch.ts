import { getAccountRecoveryRequestId } from "@virki/auth/security";
import { RECOVERY_COOKIE_NAME, requiresRecoveryRequestSwitch } from "../../lib/recovery";

type ReadableRecoveryCookies = {
  get(name: string): { value: string } | undefined;
};

// Legacy discovery deliberately excludes modern browser-bound requests. An
// unrecognized nonempty key could be an unproven, just-proven, or partially
// cookie-damaged modern recovery: a concurrent proof might commit between our
// read and a replacement Set-Cookie. Always require explicit user confirmation
// before overwriting that opaque key. This is only a navigation guard, NEVER an
// authorization proof or an exposure of the old request's identity.
export async function requiresRecoveryLinkSwitch(
  cookieStore: ReadableRecoveryCookies,
  nextLegacyId: string,
  role: "USER" | "ADMIN",
  now = new Date()
): Promise<boolean> {
  const activeKey = cookieStore.get(RECOVERY_COOKIE_NAME)?.value ?? "";
  if (!activeKey) return false;
  const activeLegacy = await getAccountRecoveryRequestId(activeKey, now, role);
  if (activeLegacy) return requiresRecoveryRequestSwitch(activeLegacy.id, nextLegacyId);
  // Includes a modern request with missing/malformed intent/browserToken as
  // well as an opaque stale key. Even a bogus key cannot bypass the verified
  // legacy candidate, same-origin + CSRF validation on explicit switch.
  return true;
}
