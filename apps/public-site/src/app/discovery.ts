import type { Metadata } from "next";

export const PUBLIC_SITE_ORIGIN = "https://biel.dev.br";
export const PUBLIC_SITE_URL = `${PUBLIC_SITE_ORIGIN}/`;
export const PUBLIC_SITEMAP_URL = `${PUBLIC_SITE_ORIGIN}/sitemap.xml`;
export const publicCanonicalLink = {
  rel: "canonical",
  href: PUBLIC_SITE_URL
};

export const publicSiteMetadata: Metadata = {
  metadataBase: new URL(PUBLIC_SITE_ORIGIN),
  title: "BielOS",
  description: "A personal operating-system-style project hub."
};
