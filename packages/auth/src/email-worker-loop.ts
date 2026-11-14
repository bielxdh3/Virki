export const EMAIL_WORKER_IDLE_POLL_MS = 5_000;
export const EMAIL_WORKER_DEFAULT_SEND_INTERVAL_MS = 250;
export const EMAIL_WORKER_FAILURE_PAUSE_MS = 1_000;
const MAX_SEND_INTERVAL_MS = 60_000;

export type EmailProcessOutcome = "idle" | "reconciled" | "contended" | "sent" | "retryable-failure" | "terminal-failure";

export type EmailWorkerLoopOptions = {
  processNext: () => Promise<EmailProcessOutcome>;
  sleep: (milliseconds: number) => Promise<void>;
  isStopping: () => boolean;
  idlePollMs?: number;
  sendIntervalMs?: number;
  failurePollMs?: number;
  onIterationError?: (error: unknown) => void;
};

// Parses VIRKI_EMAIL_MIN_SEND_INTERVAL_MS: an integer from 0 to 60000; anything else uses the default.
export function parseEmailSendIntervalMs(value: string | undefined): number {
  const trimmed = value?.trim();
  if (!trimmed || !/^\d+$/.test(trimmed)) {
    return EMAIL_WORKER_DEFAULT_SEND_INTERVAL_MS;
  }

  const parsed = Number(trimmed);
  return parsed <= MAX_SEND_INTERVAL_MS ? parsed : EMAIL_WORKER_DEFAULT_SEND_INTERVAL_MS;
}

// Drains the outbox without fixed per-message delays: sent messages are spaced by sendIntervalMs,
// idle polls wait idlePollMs, and failures pause so a broken transport is not hammered.
export async function runEmailWorkerLoop(options: EmailWorkerLoopOptions): Promise<void> {
  const idlePollMs = options.idlePollMs ?? EMAIL_WORKER_IDLE_POLL_MS;
  const sendIntervalMs = options.sendIntervalMs ?? EMAIL_WORKER_DEFAULT_SEND_INTERVAL_MS;
  const failurePollMs = options.failurePollMs ?? EMAIL_WORKER_FAILURE_PAUSE_MS;

  const pause = async (milliseconds: number) => {
    if (milliseconds > 0) {
      await options.sleep(milliseconds);
    }
  };

  while (!options.isStopping()) {
    let outcome: EmailProcessOutcome;
    try {
      outcome = await options.processNext();
    } catch (error) {
      options.onIterationError?.(error);
      await pause(failurePollMs);
      continue;
    }

    if (options.isStopping()) {
      return;
    }

    if (outcome === "reconciled") {
      // A stale exhausted item was terminalized; check the next queued item
      // immediately instead of falsely treating the outbox as empty.
      continue;
    } else if (outcome === "sent") {
      await pause(sendIntervalMs);
    } else if (outcome === "idle") {
      await pause(idlePollMs);
    } else {
      await pause(failurePollMs);
    }
  }
}
