import { prisma } from "@virki/database";
import { AuditFilterError, buildAuditQuery, parseAuditFilters, type AuditSearchParams } from "@virki/auth/audit-query";
import { requireAdminPage } from "../../../lib/admin-page";
import { AuditView, auditSelect } from "./audit-view";

export const dynamic = "force-dynamic";

export default async function AuditPage({ searchParams }: { searchParams: Promise<AuditSearchParams> }) {
  await requireAdminPage();
  let filters;
  try { filters = parseAuditFilters(await searchParams); }
  catch (error) {
    if (!(error instanceof AuditFilterError)) throw error;
    return <><h1>Auditoria</h1><p className="form-error" role="alert">{error.message}</p><a className="button-secondary" href="/admin/audit">Limpar filtros</a></>;
  }
  try {
    const rows = await prisma.auditLog.findMany({ ...buildAuditQuery(filters), select: auditSelect });
    return <AuditView filters={filters} rows={rows.slice(0, 50)} hasNext={rows.length > 50} />;
  } catch {
    return <><h1>Auditoria</h1><p className="form-error" role="alert">Não foi possível consultar os eventos. Tente novamente em instantes.</p><a className="button-secondary" href="/admin/audit">Tentar novamente</a></>;
  }
}
