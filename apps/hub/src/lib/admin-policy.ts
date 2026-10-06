import type { Surface } from "./surface";

export function isAdminRequestAllowed(surface: Surface, cloudflareAccessValid: boolean): boolean {
  return surface === "hub" && cloudflareAccessValid;
}

export function isHubAdminMutationSurface(surface: Surface): surface is "hub" {
  return surface === "hub";
}

export function isAdminRole(role: string | null | undefined): boolean {
  return role === "ADMIN";
}
