import { prisma } from "@bielos/database";

export type CoreLiveCheckState = "verified" | "unknown";

const DATABASE_PROBE_TIMEOUT_MS = 800;

export async function resolveBoundedCoreProbe(
  probe: () => Promise<unknown>,
  timeoutMs: number
): Promise<CoreLiveCheckState> {
  let timeout: ReturnType<typeof setTimeout> | undefined;

  try {
    return await Promise.race([
      probe().then(
        () => "verified" as const,
        () => "unknown" as const
      ),
      new Promise<CoreLiveCheckState>((resolve) => {
        timeout = setTimeout(() => resolve("unknown"), timeoutMs);
      })
    ]);
  } finally {
    if (timeout) {
      clearTimeout(timeout);
    }
  }
}

export async function getCoreOperationsSnapshot(): Promise<{
  hubRequest: "verified";
  authenticatedSession: "verified";
  database: CoreLiveCheckState;
}> {
  const database = await resolveBoundedCoreProbe(
    async () => {
      await prisma.$queryRaw`SELECT 1`;
    },
    DATABASE_PROBE_TIMEOUT_MS
  );

  return {
    hubRequest: "verified",
    authenticatedSession: "verified",
    database
  };
}
