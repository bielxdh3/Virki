export function getLoginRedirectPath(returnTo: string | null, recoveredFallback: string | undefined, defaultPath: string): string {
  if (recoveredFallback && returnTo) {
    const notice = new URL(recoveredFallback, "https://virki.invalid");
    notice.searchParams.set("returnTo", returnTo);
    return `${notice.pathname}${notice.search}`;
  }
  return returnTo ?? recoveredFallback ?? defaultPath;
}
