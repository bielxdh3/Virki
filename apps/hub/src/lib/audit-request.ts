import { createAuditRequestMetadata, runWithAuditContext } from "@virki/auth";
import { headers } from "next/headers";

export async function withHubAuditRequest<T>(operation: () => Promise<T>): Promise<T> {
  const metadata = createAuditRequestMetadata(await headers(), "hub-request");
  if (typeof metadata.requestId !== "string") return operation();
  return runWithAuditContext({ requestId: metadata.requestId, service: "hub", route: typeof metadata.route === "string" ? metadata.route : undefined, method: typeof metadata.method === "string" ? metadata.method : undefined }, operation);
}
