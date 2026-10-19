import type { MetadataRoute } from "next";

function readPublicOrigin(): string {
  try {
    const url = new URL(process.env.PUBLIC_SITE_URL ?? "");
    if (url.protocol === "https:" && !url.username && !url.password && url.pathname === "/" && !url.search && !url.hash) return url.origin;
  } catch {
    // Invalid optional public metadata must not break robots generation.
  }
  return "https://biel.dev.br";
}

export default function robots(): MetadataRoute.Robots {
  const publicUrl = readPublicOrigin();
  return {
    rules: {
      userAgent: "*",
      allow: "/"
    },
    sitemap: new URL("/sitemap.xml", publicUrl).href,
    host: publicUrl
  };
}
