import type { MetadataRoute } from "next";
import { readPublicOrigin } from "./public-origin";

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
