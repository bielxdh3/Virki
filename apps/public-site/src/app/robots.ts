import type { MetadataRoute } from "next";
import { PUBLIC_SITE_ORIGIN, PUBLIC_SITEMAP_URL } from "./discovery";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: {
      userAgent: "*",
      allow: "/"
    },
    sitemap: PUBLIC_SITEMAP_URL,
    host: PUBLIC_SITE_ORIGIN
  };
}
