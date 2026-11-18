/**
 * Security-sensitive OIDC provider options shared by the production issuer
 * and its protocol tests. oidc-provider supports S256 only in its runtime;
 * PKCE policy is configurable, but the accepted challenge method is not.
 */
export const OIDC_PROVIDER_SECURITY_CONFIGURATION = {
  features: {
    requestObjects: { enabled: false }
  },
  pkce: {
    required: () => true
  }
} as const;
