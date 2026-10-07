DO $$
BEGIN
  IF to_regclass('public."AuditLog"') IS NOT NULL THEN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_audit_maintenance') THEN
      RAISE EXCEPTION 'virki_audit_maintenance must be provisioned before applying AuditLog privilege boundaries';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_runtime') THEN
      EXECUTE 'REVOKE UPDATE, DELETE ON TABLE public."AuditLog" FROM virki_runtime';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_runtime_test') THEN
      EXECUTE 'REVOKE UPDATE, DELETE ON TABLE public."AuditLog" FROM virki_runtime_test';
    END IF;
    EXECUTE 'GRANT INSERT, DELETE ON TABLE public."AuditLog" TO virki_audit_maintenance';
    EXECUTE 'GRANT SELECT ("createdAt") ON TABLE public."AuditLog" TO virki_audit_maintenance';
  END IF;
END
$$;
