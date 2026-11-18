/** Only the two canonical Location forms from the Virki Hub are acceptable. */
export function isCanonicalNativeAdminRedirect(location, origin, adminPath) {
  if (typeof location !== "string" || typeof origin !== "string" ||
      !origin.startsWith("https://") || typeof adminPath !== "string" || !adminPath.startsWith("/admin/")) {
    return false;
  }
  const canonical = `/login?returnTo=${encodeURIComponent(adminPath)}`;
  return location === canonical || location === `${origin}${canonical}`;
}
