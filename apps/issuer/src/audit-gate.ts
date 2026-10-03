import type { ServerResponse } from "node:http";

const pendingAuditWrites = new WeakMap<ServerResponse, Promise<void>>();
const AUDIT_FAILURE_BODY = JSON.stringify({ error: "temporarily_unavailable" });
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

export function requireAuditBeforeResponse(response: ServerResponse, write: Promise<void>): void {
  const previous = pendingAuditWrites.get(response);
  const pending = previous ? previous.then(() => write) : write;
  pendingAuditWrites.set(response, pending);
  void pending.catch(() => undefined);
}

export function installAuditResponseGate(response: ServerResponse): void {
  const originalEnd = response.end.bind(response);
  let isEnding = false;

  response.end = ((...args: Parameters<ServerResponse["end"]>) => {
    const pending = pendingAuditWrites.get(response);
    if (!pending) return originalEnd(...args);
    if (isEnding) return response;
    isEnding = true;

    void pending.then(
      () => originalEnd(...args),
      () => {
        console.warn("OIDC audit persistence failed; the response was withheld.");
        if (response.headersSent) {
          response.destroy();
          return response;
        }
        for (const header of REPLACED_RESPONSE_HEADERS) response.removeHeader(header);
        response.statusCode = 503;
        response.statusMessage = "Service Unavailable";
        response.setHeader("content-type", "application/json; charset=utf-8");
        response.setHeader("cache-control", "no-store");
        response.setHeader("x-content-type-options", "nosniff");
        const callback = args.find((argument): argument is () => void => typeof argument === "function");
        return callback ? originalEnd(AUDIT_FAILURE_BODY, callback) : originalEnd(AUDIT_FAILURE_BODY);
      }
    ).catch(() => response.destroy());

    return response;
  }) as ServerResponse["end"];
}
