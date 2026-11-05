import { writeAuditLog, type AuditLogInput } from "@virki/auth/audit";

const AUDIT_WAIT_MS = 1_200;
const MAX_PENDING_AUDITS = 8;
const CAPACITY_WARNING_INTERVAL_MS = 30_000;

/**
 * A denied Cloudflare Access request must receive 403 even when PostgreSQL is
 * unreachable. Continue slow writes after the response deadline, but hold their
 * in-flight slots until they actually settle. This prevents unauthenticated
 * traffic from accumulating an unbounded backlog of Prisma operations.
 */
export function createBoundedAccessDenialAuditWriter(
  write: (input: AuditLogInput) => Promise<void>,
  options: { waitMs?: number; maxPending?: number; warn?: (message: string) => void } = {}
): (input: AuditLogInput) => Promise<void> {
  const waitMs = options.waitMs ?? AUDIT_WAIT_MS;
  const maxPending = options.maxPending ?? MAX_PENDING_AUDITS;
  const warn = options.warn ?? console.warn;
  let pending = 0;
  let lastCapacityWarning = Number.NEGATIVE_INFINITY;

  return async (input) => {
    if (pending >= maxPending) {
      const now = Date.now();
      if (now - lastCapacityWarning >= CAPACITY_WARNING_INTERVAL_MS) {
        lastCapacityWarning = now;
        warn("Hub Access denial audit capacity reached; denial remains enforced.");
      }
      return;
    }

    pending += 1;
    const writing = Promise.resolve()
      .then(() => write(input))
      .catch(() => { warn("Hub Access denial audit persistence failed."); })
      .finally(() => { pending -= 1; });

    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([
        writing,
        new Promise<void>((resolve) => { timer = setTimeout(resolve, waitMs); })
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  };
}

export const writeHubAccessDenialAudit = createBoundedAccessDenialAuditWriter(writeAuditLog);
