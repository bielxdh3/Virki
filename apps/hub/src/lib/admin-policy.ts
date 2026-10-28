import type { Surface } from "./surface";

export function isAdminRequestAllowed(surface: Surface, cloudflareAccessValid: boolean): boolean {
  return surface === "hub" && cloudflareAccessValid;
}

// Next may render the destination of a Server Action redirect using its
// loopback Host, while preserving proxy-validated original Hub context.
// This exception applies to page rendering only, never mutations or ingress.
export function isAdminPageRequestAllowed(
  surface: Surface,
  cloudflareAccessValid: boolean,
  trustedInternalHubRsc: boolean
): boolean {
  return isAdminRequestAllowed(surface, cloudflareAccessValid) ||
    (surface === "local" && cloudflareAccessValid && trustedInternalHubRsc);
}

export function isHubAdminMutationSurface(surface: Surface): surface is "hub" {
  return surface === "hub";
}

export function isAdminRole(role: string | null | undefined): boolean {
  return role === "ADMIN";
}
