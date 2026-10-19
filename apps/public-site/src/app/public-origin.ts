export function readPublicOrigin(env: Readonly<Record<string, string | undefined>> = process.env): string {
  try {
    const url = new URL(env.PUBLIC_SITE_URL ?? "");
    if (url.protocol === "https:" && !url.username && !url.password && url.pathname === "/" && !url.search && !url.hash) return url.origin;
  } catch {
    // Invalid optional public metadata must not break public routes.
  }
  return "https://biel.dev.br";
}
