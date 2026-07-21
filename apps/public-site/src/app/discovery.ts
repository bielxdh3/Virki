import type { Metadata } from "next";

export const PUBLIC_SITE_ORIGIN = "https://biel.dev.br";
export const PUBLIC_SITE_URL = `${PUBLIC_SITE_ORIGIN}/`;
export const PUBLIC_SITEMAP_URL = `${PUBLIC_SITE_ORIGIN}/sitemap.xml`;

export const publicSiteMetadata: Metadata = {
  metadataBase: new URL(PUBLIC_SITE_ORIGIN),
  alternates: {
    canonical: PUBLIC_SITE_URL
  },
  title: "BielOS",
  description: "A personal operating-system-style project hub."
};
