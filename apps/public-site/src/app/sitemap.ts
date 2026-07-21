import type { MetadataRoute } from "next";
import { PUBLIC_SITE_URL } from "./discovery";

export default function sitemap(): MetadataRoute.Sitemap {
  return [{ url: PUBLIC_SITE_URL }];
}
