import { writeAuditLog, type AuditLogInput } from "@virki/auth/audit";
import { createBoundedAccessDenialAuditWriter } from "./access-denial-audit";

const AUDIT_WINDOW_MS = 60_000;
const MAX_EVENTS_PER_WINDOW = 120;

/**
 * Public native login/CSRF denials must always reject the request, but best-effort
 * audit writes cannot become an unbounded PostgreSQL workload before login rate
 * limiting. Keep both a per-process time budget and occupied in-flight slots;
 * the general authenticated/transactional security audit is never sampled.
 */
export function createBoundedPreauthDenialAuditWriter(
  write: (input: AuditLogInput) => Promise<void>,
  options: {
    now?: () => number; windowMs?: number; maxEvents?: number;
    waitMs?: number; maxPending?: number; warn?: (message: string) => void;
  } = {}
): (input: AuditLogInput) => Promise<void> {
  const now = options.now ?? Date.now;
  const windowMs = options.windowMs ?? AUDIT_WINDOW_MS;
  const maxEvents = options.maxEvents ?? MAX_EVENTS_PER_WINDOW;
  const warn = options.warn ?? console.warn;
  const bounded = createBoundedAccessDenialAuditWriter(write, {
    label: "Hub pre-auth security", warn, waitMs: options.waitMs, maxPending: options.maxPending
  });
  let windowStart = now();
  let accepted = 0;
  let warned = false;

  return async (input) => {
    const current = now();
    if (current < windowStart || current - windowStart >= windowMs) {
      windowStart = current;
      accepted = 0;
      warned = false;
    }
    if (accepted >= maxEvents) {
      if (!warned) {
        warned = true;
        warn("Hub pre-auth security denial audit rate ceiling reached; denial remains enforced.");
      }
      return;
    }
    accepted += 1;
    await bounded(input);
  };
}

export const writePreauthDenialAudit = createBoundedPreauthDenialAuditWriter(writeAuditLog);
