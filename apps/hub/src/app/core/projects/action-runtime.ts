import { revalidatePath } from "next/cache";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";
import { getCurrentSession } from "../../../lib/auth";
import {
  isCloudflareAccessAllowed,
  validateHubCloudflareAccess
} from "../../../lib/cloudflare-access";

export const actionRuntime = {
  getRequestHeaders: () => headers(),
  deny: (): never => forbidden(),
  go: (location: string): never => redirect(location),
  revalidate: (path: string): void => revalidatePath(path),
  getSession: () => getCurrentSession(),
  validateAccess: (requestHeaders: Pick<Headers, "get">, source: string) =>
    validateHubCloudflareAccess(requestHeaders, source),
  accessAllowed: (result: Awaited<ReturnType<typeof validateHubCloudflareAccess>>) =>
    isCloudflareAccessAllowed(result)
};
