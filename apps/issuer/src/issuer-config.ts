export const DEFAULT_DEVELOPMENT_ISSUER = "https://portal.biel.dev.br";

export function readIssuer(env: NodeJS.ProcessEnv): string {
  const configured = env.VIRKI_OIDC_ISSUER?.trim();
  if (env.NODE_ENV === "production" && !configured) throw new Error("OIDC issuer URL is required in production.");
  const issuerUrl = new URL(configured || DEFAULT_DEVELOPMENT_ISSUER);
  if (issuerUrl.username || issuerUrl.password || issuerUrl.search || issuerUrl.hash || issuerUrl.pathname !== "/") throw new Error("OIDC issuer URL is invalid.");
  if (env.NODE_ENV === "production" && issuerUrl.protocol !== "https:") throw new Error("OIDC issuer requires HTTPS in production.");
  return issuerUrl.origin;
}
