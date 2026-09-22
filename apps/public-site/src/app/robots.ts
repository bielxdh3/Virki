import type { MetadataRoute } from "next";

const publicUrl = process.env.PUBLIC_SITE_URL ?? "https://biel.dev.br";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: {
      userAgent: "*",
      allow: "/"
    },
    sitemap: new URL("/sitemap.xml", publicUrl).href,
    host: publicUrl
  };
}
