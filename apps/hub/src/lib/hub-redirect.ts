export function createHubRedirectUrl(
  pathname: string,
  requestUrl: string,
  env: Readonly<Record<string, string | undefined>> = process.env
): URL {
  const configuredOrigin = parseConfiguredHubOrigin(env.NEXT_PUBLIC_HUB_URL);
  return new URL(pathname, configuredOrigin ?? requestUrl);
}

function parseConfiguredHubOrigin(value: string | undefined): string | undefined {
  const trimmed = value?.trim();

  if (!trimmed) {
    return undefined;
  }

  try {
    const url = new URL(trimmed);
    const hasSafeProtocol = url.protocol === "https:" || url.protocol === "http:";
    const isOriginOnly = url.pathname === "/" && !url.search && !url.hash;

    if (!hasSafeProtocol || !isOriginOnly || url.username || url.password) {
      return undefined;
    }

    return url.origin;
  } catch {
    return undefined;
  }
}
