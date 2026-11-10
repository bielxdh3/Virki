// Test-only physical PostgreSQL witness for two competing ADMIN recovery writers.
// The observer uses its own PrismaClient; the app's small connection pool may be
// entirely occupied by the holder and the two real lock waiters.
import { prisma, Prisma, type PrismaClient } from "@virki/database";

export function isExpectedRecoveryRaceRejection(error: unknown): boolean {
  // A SERIALIZABLE loser may abort with 40001 before observing the newly
  // consumed proof; a pool timeout or unrelated query failure is not a win.
  return error instanceof Prisma.PrismaClientKnownRequestError &&
    (error.code === "P2034" || (error.code === "P2010" && error.meta?.code === "40001"));
}

export async function boundedRaceWait<T>(promise: Promise<T>, label: string, timeoutMs = 20_000): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`Timed out: ${label}`)), timeoutMs);
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export function holdAdminUserRow(userId: string, observer: PrismaClient) {
  let unlock!: () => void;
  const gate = new Promise<void>((resolve) => { unlock = resolve; });
  let lockAcquired!: (pid: number) => void;
  const acquired = new Promise<number>((resolve) => { lockAcquired = resolve; });
  const holder = prisma.$transaction(async (tx) => {
    const rows = await tx.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid()::int AS pid`;
    if (rows.length !== 1) throw new Error("No PostgreSQL backend PID for ADMIN lock holder");
    await tx.$queryRaw`SELECT "id" FROM "User" WHERE "id" = ${userId} FOR UPDATE`;
    lockAcquired(rows[0]!.pid);
    await gate;
  }, { timeout: 60_000 }).then(
    () => ({ ok: true as const, error: null }),
    (error: unknown) => ({ ok: false as const, error })
  );

  return {
    async acquiredPid() {
      // Reject promptly if the holder fails before signaling acquisition.
      return boundedRaceWait(Promise.race([
        acquired,
        holder.then((result) => { throw result.error ?? new Error("ADMIN lock holder settled before acquisition"); })
      ]), "ADMIN User row lock acquisition", 8_000);
    },
    async observeTwoWaiters(holderPid: number) {
      const deadline = Date.now() + 18_000;
      while (Date.now() < deadline) {
        const rows = await boundedRaceWait(observer.$queryRaw<Array<{ pid: number; blockers: number[] }>>`
          SELECT pid::int AS pid, pg_blocking_pids(pid) AS blockers
          FROM pg_stat_activity
          WHERE datname = current_database() AND pid <> ${holderPid}
            AND wait_event_type = 'Lock'
            AND query LIKE '%FROM "User"%' AND query LIKE '%FOR UPDATE%'
        `, "independent PostgreSQL lock observation", 4_000);
        const byPid = new Map(rows.map((row) => [row.pid, row.blockers]));
        const reachesHolder = (pid: number, seen = new Set<number>()): boolean => {
          if (seen.has(pid)) return false;
          seen.add(pid);
          return (byPid.get(pid) ?? []).some((blocker) => blocker === holderPid || reachesHolder(blocker, seen));
        };
        const distinctWaiters = rows.filter((row) => reachesHolder(row.pid));
        if (new Set(distinctWaiters.map((row) => row.pid)).size >= 2 &&
            distinctWaiters.some((row) => row.blockers.includes(holderPid))) {
          return distinctWaiters.map((row) => row.pid);
        }
        await new Promise<void>((resolve) => setTimeout(resolve, 20));
      }
      throw new Error("Two distinct ADMIN recovery PostgreSQL actors were not physically blocked on the held User row");
    },
    async release() {
      unlock();
      const result = await boundedRaceWait(holder, "ADMIN User lock holder cleanup", 65_000);
      if (!result.ok) throw result.error;
    }
  };
}
