import type { MetadataRoute } from "next";
import { readPublicOrigin } from "./public-origin";

export default function sitemap(): MetadataRoute.Sitemap {
  return [{ url: readPublicOrigin() }];
}
