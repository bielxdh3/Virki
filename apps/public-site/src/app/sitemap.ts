import type { MetadataRoute } from "next";

const publicUrl = process.env.PUBLIC_SITE_URL ?? "https://biel.dev.br";

export default function sitemap(): MetadataRoute.Sitemap {
  return [{ url: publicUrl }];
}
