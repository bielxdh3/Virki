import { isNativeHubPerimeterEnabled } from "./hub-perimeter";

/** Do not sample a verified ADMIN denial; budget only native public ingress. */
export function shouldBoundNativePasskeyDenial(
  adminAction: boolean, surface: string, actorRole: string | undefined,
  nativeEnabled = isNativeHubPerimeterEnabled()
): boolean {
  return adminAction && surface === "hub" && nativeEnabled && actorRole !== "ADMIN";
}
