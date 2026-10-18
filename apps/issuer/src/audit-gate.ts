import type { ServerResponse } from "node:http";

const pendingAuditWrites = new WeakMap<ServerResponse, Promise<void>>();
const pendingAuditWaiters = new WeakMap<ServerResponse, () => void>();
const AUDIT_FAILURE_BODY = JSON.stringify({ error: "temporarily_unavailable" });
const MAX_PENDING_RESPONSE_BYTES = 1024 * 1024;
const REPLACED_RESPONSE_HEADERS = [
  "content-length",
  "content-type",
  "content-encoding",
  "content-range",
  "etag",
  "location",
  "set-cookie",
  "transfer-encoding"
];

type BufferedResponseOperation = {
  bytes: number;
  replay: () => void;
  discard: (error: Error) => void;
};

export function requireAuditBeforeResponse(response: ServerResponse, write: Promise<void>): void {
  const previous = pendingAuditWrites.get(response);
  const pending = Promise.all(previous ? [previous, write] : [write]).then(() => undefined);
  pendingAuditWrites.set(response, pending);
  void pending.catch(() => undefined);
  pendingAuditWaiters.get(response)?.();
}

export function installAuditResponseGate(response: ServerResponse): void {
  const originalEnd = response.end.bind(response);
  const originalWrite = response.write.bind(response);
  const originalWriteHead = response.writeHead.bind(response);
  const originalFlushHeaders = response.flushHeaders.bind(response);
  let state: "open" | "waiting" | "failed" | "closed" = "open";
  let bufferedBytes = 0;
  let queue: BufferedResponseOperation[] = [];
  let observedAuditPromise: Promise<void> | undefined;

  function discardBufferedResponse(error: Error): void {
    const operations = queue;
    queue = [];
    bufferedBytes = 0;
    discardOperations(operations, error);
  }

  function discardOperations(operations: BufferedResponseOperation[], error: Error): void {
    for (const operation of operations) {
      try {
        operation.discard(error);
      } catch {
        // One response callback must not prevent the remaining callbacks from settling.
      }
    }
  }

  function closeBufferedResponse(): void {
    if (state === "failed" || state === "closed") return;
    state = "closed";
    pendingAuditWrites.delete(response);
    pendingAuditWaiters.delete(response);
    discardBufferedResponse(new Error("OIDC response closed before required audit persistence completed."));
  }

  response.once("close", () => {
    if (!response.writableFinished) closeBufferedResponse();
  });

  function isResponseClosed(): boolean {
    return state === "closed" || response.destroyed || response.writableEnded || response.writableFinished;
  }

  function waitForLatestAudit(): void {
    if (state !== "waiting") return;
    if (isResponseClosed()) {
      closeBufferedResponse();
      return;
    }
    const pending = pendingAuditWrites.get(response);
    if (!pending) {
      pendingAuditWaiters.delete(response);
      releaseBufferedResponse();
      return;
    }
    if (pending === observedAuditPromise) return;
    observedAuditPromise = pending;
    void pending.then(
      () => {
        if (state !== "waiting") return;
        if (pendingAuditWrites.get(response) === pending) pendingAuditWrites.delete(response);
        if (observedAuditPromise === pending) observedAuditPromise = undefined;
        waitForLatestAudit();
      },
      () => failClosed()
    ).catch(() => response.destroy());
  }

  function beginWaitingForAudit(): boolean {
    const pending = pendingAuditWrites.get(response);
    if (!pending || state === "failed" || state === "closed") return false;
    if (state === "open") {
      state = "waiting";
      pendingAuditWaiters.set(response, waitForLatestAudit);
      waitForLatestAudit();
    }
    return state === "waiting";
  }

  function releaseBufferedResponse(): void {
    if (state !== "waiting") return;
    if (pendingAuditWrites.has(response)) {
      waitForLatestAudit();
      return;
    }
    if (isResponseClosed()) {
      closeBufferedResponse();
      return;
    }
    state = "open";
    pendingAuditWrites.delete(response);
    const operations = queue;
    queue = [];
    bufferedBytes = 0;
    try {
      for (let index = 0; index < operations.length; index++) {
        if (response.destroyed || response.writableEnded || response.writableFinished) {
          discardOperations(operations.slice(index), new Error("OIDC response already ended before all audited response data was released."));
          return;
        }
        operations[index]!.replay();
      }
    } catch (error) {
      response.destroy(error instanceof Error ? error : new Error("OIDC response replay failed."));
    }
  }

  function failClosed(): void {
    if (state === "failed" || state === "closed") return;
    state = "failed";
    pendingAuditWrites.delete(response);
    pendingAuditWaiters.delete(response);
    discardBufferedResponse(new Error("OIDC response withheld because required audit persistence failed."));
    if (response.headersSent) {
      console.warn("OIDC audit persistence failed after response headers were sent; the response was terminated.");
      response.destroy();
      return;
    }
    console.warn("OIDC audit persistence failed; the response was withheld.");
    for (const header of REPLACED_RESPONSE_HEADERS) response.removeHeader(header);
    response.statusCode = 503;
    response.statusMessage = "Service Unavailable";
    response.setHeader("content-type", "application/json; charset=utf-8");
    response.setHeader("cache-control", "no-store");
    response.setHeader("x-content-type-options", "nosniff");
    originalWriteHead(503);
    originalEnd(AUDIT_FAILURE_BODY);
  }

  function enqueue(bytes: number, replay: () => void, discard: (error: Error) => void = () => undefined): void {
    if (bufferedBytes + bytes > MAX_PENDING_RESPONSE_BYTES) {
      queue.push({ bytes: 0, replay: () => undefined, discard });
      failClosed();
      return;
    }
    bufferedBytes += bytes;
    queue.push({ bytes, replay, discard });
  }

  response.writeHead = ((...args: Parameters<ServerResponse["writeHead"]>) => {
    if (state === "failed" || isResponseClosed()) return response;
    if (!beginWaitingForAudit()) return originalWriteHead(...args);
    enqueue(0, () => { originalWriteHead(...args); });
    return response;
  }) as ServerResponse["writeHead"];

  response.flushHeaders = (() => {
    if (state === "failed" || isResponseClosed()) return;
    if (!beginWaitingForAudit()) return originalFlushHeaders();
    enqueue(0, () => originalFlushHeaders());
  }) as ServerResponse["flushHeaders"];

  response.write = ((...args: Parameters<ServerResponse["write"]>) => {
    if (state === "failed" || isResponseClosed()) {
      getCallback(args)?.(new Error(state === "failed" ? "OIDC response was withheld because required audit persistence failed." : "OIDC response is already closed."));
      return false;
    }
    if (!beginWaitingForAudit()) return originalWrite(...args);
    const bytes = getChunkByteLength(args[0], args[1]);
    const callback = getCallback(args);
    if (!Number.isSafeInteger(bytes) || bufferedBytes + bytes > MAX_PENDING_RESPONSE_BYTES) {
      failClosed();
      callback?.(new Error("OIDC response exceeded the bounded audit buffer."));
      return false;
    }
    enqueue(bytes, () => { originalWrite(...args); }, (error) => callback?.(error));
    return true;
  }) as ServerResponse["write"];

  response.end = ((...args: Parameters<ServerResponse["end"]>) => {
    if (state === "failed" || isResponseClosed()) {
      getCallback(args)?.(new Error(state === "failed" ? "OIDC response was withheld because required audit persistence failed." : "OIDC response is already closed."));
      return response;
    }
    if (!beginWaitingForAudit()) return originalEnd(...args);
    enqueue(getChunkByteLength(args[0], args[1]), () => { originalEnd(...args); }, (error) => getCallback(args)?.(error));
    return response;
  }) as ServerResponse["end"];
}

function getChunkByteLength(chunk: unknown, encodingOrCallback?: unknown): number {
  if (chunk === undefined || chunk === null || typeof chunk === "function") return 0;
  if (typeof chunk === "string") {
    const encoding = typeof encodingOrCallback === "string" ? encodingOrCallback as BufferEncoding : "utf8";
    try {
      return Buffer.byteLength(chunk, encoding);
    } catch {
      return Number.NaN;
    }
  }
  if (Buffer.isBuffer(chunk) || ArrayBuffer.isView(chunk)) return chunk.byteLength;
  if (chunk instanceof ArrayBuffer) return chunk.byteLength;
  return Number.NaN;
}

function getCallback(args: readonly unknown[]): ((error?: Error) => void) | undefined {
  const candidate = args.at(-1);
  return typeof candidate === "function" ? candidate as (error?: Error) => void : undefined;
}
