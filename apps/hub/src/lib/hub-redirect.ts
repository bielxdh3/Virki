export type HubRedirectPath = "/" | "/login";

const INVALID_CONFIGURATION_MESSAGE = "Invalid hub redirect configuration.";
const INVALID_DESTINATION_MESSAGE = "Invalid hub redirect destination.";

export function createHubRedirectUrl(
  pathname: HubRedirectPath,
  requestUrl: string,
  env: Readonly<Record<string, string | undefined>> = process.env
): URL {
  assertHubRedirectPath(pathname);
  return new URL(pathname, resolveHubOrigin(requestUrl, env));
}

function resolveHubOrigin(
  requestUrl: string,
  env: Readonly<Record<string, string | undefined>>
): string {
  const configuredValue = env.NEXT_PUBLIC_HUB_URL;
  const isProduction = env.NODE_ENV === "production";

  if (configuredValue !== undefined && hasControlCharacters(configuredValue)) {
    throw new Error(INVALID_CONFIGURATION_MESSAGE);
  }

  const trimmed = configuredValue?.trim();

  if (!trimmed) {
    if (isProduction) {
      throw new Error(INVALID_CONFIGURATION_MESSAGE);
    }

    return parseLocalRequestOrigin(requestUrl);
  }

  try {
    const url = new URL(trimmed);
    const hasSafeProtocol = url.protocol === "https:" || url.protocol === "http:";
    const isOriginOnly = url.pathname === "/" && !url.search && !url.hash;
    const hasRequiredProductionProtocol = !isProduction || url.protocol === "https:";

    if (
      !hasSafeProtocol ||
      !hasRequiredProductionProtocol ||
      !isOriginOnly ||
      url.username ||
      url.password
    ) {
      throw new Error(INVALID_CONFIGURATION_MESSAGE);
    }

    return url.origin;
  } catch {
    throw new Error(INVALID_CONFIGURATION_MESSAGE);
  }
}

function hasControlCharacters(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 0x1f || codePoint === 0x7f;
  });
}

function parseLocalRequestOrigin(requestUrl: string): string {
  try {
    const url = new URL(requestUrl);

    if (
      (url.protocol !== "https:" && url.protocol !== "http:") ||
      url.username ||
      url.password
    ) {
      throw new Error(INVALID_CONFIGURATION_MESSAGE);
    }

    return url.origin;
  } catch {
    throw new Error(INVALID_CONFIGURATION_MESSAGE);
  }
}

function assertHubRedirectPath(pathname: HubRedirectPath): void {
  if (pathname !== "/" && pathname !== "/login") {
    throw new Error(INVALID_DESTINATION_MESSAGE);
  }
}
