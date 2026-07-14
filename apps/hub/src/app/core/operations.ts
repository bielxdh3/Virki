import { prisma } from "@bielos/database";

export type CoreLiveCheckState = "verified" | "unknown";

const DATABASE_PROBE_TIMEOUT_MS = 800;

export function createSingleFlightProbe(
  probe: () => Promise<unknown>
): () => Promise<unknown> {
  let inFlight: Promise<unknown> | undefined;

  return () => {
    if (inFlight) {
      return inFlight;
    }

    const current = Promise.resolve().then(probe);
    inFlight = current;

    const clearCurrent = () => {
      if (inFlight === current) {
        inFlight = undefined;
      }
    };

    void current.then(clearCurrent, clearCurrent);
    return current;
  };
}

export async function resolveBoundedCoreProbe(
  probe: () => Promise<unknown>,
  timeoutMs: number
): Promise<CoreLiveCheckState> {
  let timeout: ReturnType<typeof setTimeout> | undefined;

  try {
    const probeResult = Promise.resolve().then(probe);

    return await Promise.race([
      probeResult.then(
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

const runDatabaseProbe = createSingleFlightProbe(async () => {
  await prisma.$queryRaw`SELECT 1`;
});

export async function getCoreOperationsSnapshot(): Promise<{
  hubRequest: "verified";
  authenticatedSession: "verified";
  database: CoreLiveCheckState;
}>;
export async function getCoreOperationsSnapshot(
  databaseProbe: () => Promise<unknown>,
  timeoutMs?: number
): Promise<{
  hubRequest: "verified";
  authenticatedSession: "verified";
  database: CoreLiveCheckState;
}>;
export async function getCoreOperationsSnapshot(
  databaseProbe = runDatabaseProbe,
  timeoutMs = DATABASE_PROBE_TIMEOUT_MS
) {
  const database = await resolveBoundedCoreProbe(databaseProbe, timeoutMs);

  return {
    hubRequest: "verified",
    authenticatedSession: "verified",
    database
  };
}
