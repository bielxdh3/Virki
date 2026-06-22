export type AuthBoundary = "local-placeholder" | "cloudflare-access";

export type AuthSessionPrincipal = {
  userId: string;
  email: string;
  boundary: AuthBoundary;
};

export function isAuthEnabled(): boolean {
  return Boolean(process.env.AUTH_SESSION_SECRET);
}
