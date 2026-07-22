import type { CloudflareAccessJwtResult } from "@bielos/auth/cloudflare-access";

type GymForgeAccessDependencies = {
  validateAccess: (
    requestHeaders: Pick<Headers, "get">,
    source: string
  ) => Promise<CloudflareAccessJwtResult>;
  isAccessAllowed: (result: CloudflareAccessJwtResult) => boolean;
  deny: () => never;
};

export async function requireGymForgeMutationAccess(
  requestHeaders: Pick<Headers, "get">,
  source: string,
  dependencies: GymForgeAccessDependencies
): Promise<void> {
  const accessResult = await dependencies.validateAccess(requestHeaders, source);

  if (!dependencies.isAccessAllowed(accessResult)) {
    dependencies.deny();
  }
}
