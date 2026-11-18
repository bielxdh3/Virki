const SESSION_TOKEN_SHAPE = /^[A-Za-z0-9_-]{43}$/u;
const DEFAULT_WAIT_MS = 1_200;
const DEFAULT_WINDOW_MS = 60_000;
const DEFAULT_MAX_LOOKUPS = 480;
const DEFAULT_MAX_PENDING = 8;

/**
 * A hostile Origin must not turn a syntactically plausible cookie into an
 * unbounded stream of PostgreSQL session SELECTs. Attribution is best effort:
 * when capacity is exhausted the caller still denies the request and records
 * an anonymous denial. This is a per-process budget, not a distributed limit.
 */
export function createBoundedDenialSessionLookup<T>(
  lookup: (token: string) => Promise<T | null>,
  options: {
    now?: () => number; waitMs?: number; windowMs?: number;
    maxLookups?: number; maxPending?: number; warn?: (message: string) => void;
  } = {}
): (token?: string) => Promise<T | null> {
  const now = options.now ?? Date.now;
  const waitMs = options.waitMs ?? DEFAULT_WAIT_MS;
  const windowMs = options.windowMs ?? DEFAULT_WINDOW_MS;
  const maxLookups = options.maxLookups ?? DEFAULT_MAX_LOOKUPS;
  const maxPending = options.maxPending ?? DEFAULT_MAX_PENDING;
  const warn = options.warn ?? console.warn;
  let windowStart = now();
  let accepted = 0;
  let pending = 0;
  let warned = false;

  return async (token) => {
    if (!token || !SESSION_TOKEN_SHAPE.test(token)) return null;
    const current = now();
    if (current < windowStart || current - windowStart >= windowMs) {
      windowStart = current;
      accepted = 0;
      warned = false;
    }
    if (accepted >= maxLookups || pending >= maxPending) {
      if (!warned) {
        warned = true;
        warn("Hub denial session attribution capacity reached; denial remains enforced.");
      }
      return null;
    }
    accepted += 1;
    pending += 1;
    // Retain the actual PostgreSQL slot even if the response deadline wins.
    const reading = Promise.resolve().then(() => lookup(token))
      .catch(() => null)
      .finally(() => { pending -= 1; });
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        reading,
        new Promise<null>((resolve) => { timer = setTimeout(() => resolve(null), waitMs); })
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  };
}
