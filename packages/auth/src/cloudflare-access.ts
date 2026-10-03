import { createRemoteJWKSet, jwtVerify } from "jose";

export type CloudflareAccessJwtStatus =
  | "disabled"
  | "valid"
  | "missing"
  | "invalid"
  | "misconfigured";

export type CloudflareAccessJwtReason =
  | "missing-cloudflare-access-config"
  | "missing-cloudflare-access-jwt"
  | "invalid-cloudflare-access-jwt"
  | "expired-cloudflare-access-jwt"
  | "invalid-cloudflare-access-audience"
  | "invalid-cloudflare-access-issuer"
  | "inactive-cloudflare-access-jwt"
  | "invalid-cloudflare-access-signature"
  | "missing-cloudflare-access-signing-key";

export type CloudflareAccessJwtResult = {
  allowed: boolean;
  required: boolean;
  status: CloudflareAccessJwtStatus;
  reason?: CloudflareAccessJwtReason;
};

type CloudflareAccessConfig = {
  required: boolean;
  audience: string;
  teamDomain: string;
};

const CF_ACCESS_JWT_HEADER = "cf-access-jwt-assertion";

const globalForCloudflareAccess = globalThis as unknown as {
  bielosCloudflareAccessJwks?: Map<string, ReturnType<typeof createRemoteJWKSet>>;
};

export async function validateCloudflareAccessJwt(
  headers: Pick<Headers, "get">,
  env: NodeJS.ProcessEnv = process.env
): Promise<CloudflareAccessJwtResult> {
  const config = getCloudflareAccessConfig(env);

  if (!config.required) {
    return {
      allowed: true,
      required: false,
      status: "disabled"
    };
  }

  if (!config.audience || !config.teamDomain) {
    return {
      allowed: false,
      required: true,
      status: "misconfigured",
      reason: "missing-cloudflare-access-config"
    };
  }

  const token = headers.get(CF_ACCESS_JWT_HEADER);

  if (!token) {
    return {
      allowed: false,
      required: true,
      status: "missing",
      reason: "missing-cloudflare-access-jwt"
    };
  }

  try {
    await jwtVerify(token, getJwks(config.teamDomain), {
      audience: config.audience,
      issuer: config.teamDomain
    });

    return {
      allowed: true,
      required: true,
      status: "valid"
    };
  } catch (error) {
    return {
      allowed: false,
      required: true,
      status: "invalid",
      reason: classifyCloudflareAccessJwtError(error)
    };
  }
}

export function classifyCloudflareAccessJwtError(error: unknown): CloudflareAccessJwtReason {
  if (!isJoseError(error)) {
    return "invalid-cloudflare-access-jwt";
  }

  if (error.code === "ERR_JWT_EXPIRED") {
    return "expired-cloudflare-access-jwt";
  }

  if (error.code === "ERR_JWT_CLAIM_VALIDATION_FAILED") {
    if (error.claim === "aud") {
      return "invalid-cloudflare-access-audience";
    }

    if (error.claim === "iss") {
      return "invalid-cloudflare-access-issuer";
    }

    if (error.claim === "nbf") {
      return "inactive-cloudflare-access-jwt";
    }
  }

  if (error.code === "ERR_JWS_SIGNATURE_VERIFICATION_FAILED") {
    return "invalid-cloudflare-access-signature";
  }

  if (error.code === "ERR_JWKS_NO_MATCHING_KEY") {
    return "missing-cloudflare-access-signing-key";
  }

  return "invalid-cloudflare-access-jwt";
}

export function isCloudflareAccessJwtRequired(
  env: NodeJS.ProcessEnv = process.env
): boolean {
  return env.NODE_ENV === "production" || env.CLOUDFLARE_ACCESS_JWT_REQUIRED === "true";
}

function getCloudflareAccessConfig(env: NodeJS.ProcessEnv): CloudflareAccessConfig {
  return {
    required: isCloudflareAccessJwtRequired(env),
    audience: env.CLOUDFLARE_ACCESS_AUDIENCE?.trim() ?? "",
    teamDomain: normalizeTeamDomain(env.CLOUDFLARE_TEAM_DOMAIN)
  };
}

function normalizeTeamDomain(value: string | undefined): string {
  const trimmed = value?.trim();

  if (!trimmed) {
    return "";
  }

  const withProtocol = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;

  return withProtocol.replace(/\/+$/, "");
}

function getJwks(teamDomain: string): ReturnType<typeof createRemoteJWKSet> {
  const cache = getJwksCache();
  const cached = cache.get(teamDomain);

  if (cached) {
    return cached;
  }

  const jwks = createRemoteJWKSet(new URL(`${teamDomain}/cdn-cgi/access/certs`));
  cache.set(teamDomain, jwks);
  return jwks;
}

function getJwksCache(): Map<string, ReturnType<typeof createRemoteJWKSet>> {
  globalForCloudflareAccess.bielosCloudflareAccessJwks ??= new Map();
  return globalForCloudflareAccess.bielosCloudflareAccessJwks;
}

function isJoseError(error: unknown): error is { code: string; claim?: string } {
  return typeof error === "object" && error !== null && "code" in error && typeof error.code === "string";
}
