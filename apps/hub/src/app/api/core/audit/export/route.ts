import { NextResponse, type NextRequest } from "next/server";

import { writeAuditLog } from "@bielos/auth";
import { CSRF_FORM_FIELD_NAME, validateCsrfToken } from "@bielos/auth/csrf";
import { getCurrentSession } from "../../../../../lib/auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../../../lib/cloudflare-access";
import { CORE_AUDIT_EXPORT_LIMIT, listCoreAuditActivityPage, parseAuditDate } from "../../../../core/security/audit-service";
import { normalizeCoreAuditFilter } from "../../../../core/security/audit-view";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  const access = await validateHubCloudflareAccess(request.headers, "core-audit-export");
  if (!isCloudflareAccessAllowed(access)) return new NextResponse("Forbidden", { status: 403 });
  const formData = await request.formData();
  if (!validateCsrfToken(readFormString(formData, CSRF_FORM_FIELD_NAME)).valid) {
    return new NextResponse("Forbidden", { status: 403 });
  }
  const session = await getCurrentSession();
  if (!session || session.user.role !== "OWNER") return new NextResponse("Forbidden", { status: 403 });

  const options = {
    requestedFilter: normalizeCoreAuditFilter(readFormString(formData, "audit")),
    category: readFormString(formData, "category") || undefined,
    result: readFormString(formData, "result") || undefined,
    actor: readFormString(formData, "actor") || undefined,
    resource: readFormString(formData, "resource") || undefined,
    event: readFormString(formData, "event") || undefined,
    search: readFormString(formData, "search") || undefined,
    from: parseAuditDate(readFormString(formData, "from")),
    to: parseAuditDate(readFormString(formData, "to"), true)
  } as const;
  const rows = [] as Awaited<ReturnType<typeof listCoreAuditActivityPage>>["items"];
  let cursor: string | undefined;
  while (rows.length < CORE_AUDIT_EXPORT_LIMIT) {
    const page = await listCoreAuditActivityPage(session.user, { ...options, cursor });
    rows.push(...page.items.slice(0, CORE_AUDIT_EXPORT_LIMIT - rows.length));
    if (!page.nextCursor || page.items.length === 0) break;
    cursor = page.nextCursor;
  }

  await writeAuditLog({
    eventType: "AUDIT_LOG_EXPORTED",
    result: "INFO",
    actorUserId: session.user.id,
    resource: "audit",
    message: "Owner exported a bounded sanitized audit interval.",
    metadata: { rowCount: rows.length, filter: options.requestedFilter }
  });

  const csv = [
    "timestamp,category,event,result,resource,actor",
    ...rows.map((row) => [row.createdAt.toISOString(), row.category, row.eventLabel, row.result, row.resource, row.actorState].map(escapeCsv).join(","))
  ].join("\n");
  return new NextResponse(`${csv}\n`, {
    status: 200,
    headers: {
      "content-type": "text/csv; charset=utf-8",
      "content-disposition": "attachment; filename=\"bielos-audit.csv\"",
      "cache-control": "no-store"
    }
  });
}

function readFormString(formData: FormData, key: string): string {
  const value = formData.get(key);
  return typeof value === "string" ? value.trim() : "";
}

function escapeCsv(value: string): string {
  const normalized = value.replaceAll(/[\r\n]/gu, " ");
  return /[",]/u.test(normalized) ? `"${normalized.replaceAll('"', '""')}"` : normalized;
}
