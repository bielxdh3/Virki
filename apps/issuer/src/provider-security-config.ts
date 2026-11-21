/**
 * Security-sensitive OIDC provider options shared by the production issuer
 * and its protocol tests. oidc-provider supports S256 only in its runtime;
 * PKCE policy is configurable, but the accepted challenge method is not.
 */
function issuerClientBasedCORS(context: unknown, origin: string, client: unknown): boolean {
  if (origin === "null" || !context || typeof context !== "object" || !client || typeof client !== "object") return false;
  const oidcContext = context as { oidc?: { route?: unknown } };
  const oidcClient = client as { clientAuthMethod?: unknown; redirectUris?: unknown };
  const userinfo = oidcContext.oidc?.route === "userinfo";
  const publicClient = oidcClient.clientAuthMethod === "none";
  if (!userinfo && !publicClient) return false;
  if (!Array.isArray(oidcClient.redirectUris)) return false;
  return oidcClient.redirectUris.some((redirectUri) => {
    if (typeof redirectUri !== "string") return false;
    try {
      return new URL(redirectUri).origin === origin;
    } catch {
      return false;
    }
  });
}

export const OIDC_PROVIDER_SECURITY_CONFIGURATION = {
  clientBasedCORS: issuerClientBasedCORS,
  features: {
    requestObjects: { enabled: false }
  },
  pkce: {
    required: () => true
  }
} as const;
