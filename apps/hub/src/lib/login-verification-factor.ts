export type ServerLoginFactor = "email" | "totp" | "backup";
export type DisplayedLoginFactor = ServerLoginFactor | "recovery";

// The URL selects only the destructive recovery sub-flow when TOTP is the
// server-bound factor. A query string must never authorize another factor.
export function displayedLoginFactor(
  serverFactor: ServerLoginFactor | null,
  requestedFactor: string | undefined
): DisplayedLoginFactor | null {
  if (!serverFactor) return null;
  if (requestedFactor === "recovery" && serverFactor === "totp") return "recovery";
  return serverFactor;
}
