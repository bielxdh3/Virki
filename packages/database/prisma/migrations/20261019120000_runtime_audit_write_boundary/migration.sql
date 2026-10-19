DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_runtime') THEN
    IF to_regclass('public."AuditLog"') IS NOT NULL THEN
      EXECUTE 'REVOKE INSERT ON TABLE public."AuditLog" FROM virki_runtime';
      EXECUTE 'REVOKE INSERT ("createdAt") ON TABLE public."AuditLog" FROM virki_runtime';
      EXECUTE 'GRANT INSERT ("id", "eventType", "actorUserId", "actorEmailHash", "result", "resource", "message", "metadata", "schemaVersion", "category", "severity", "action", "reason", "actorRef", "actorRole", "targetRef", "sessionRef", "deviceRef", "requestId", "service", "route", "method", "networkProvenance", "beforeState", "afterState") ON TABLE public."AuditLog" TO virki_runtime';
      EXECUTE 'GRANT INSERT ("createdAt") ON TABLE public."AuditLog" TO virki_runtime';
    END IF;

    IF to_regclass('public."SanitizedAuditReference"') IS NOT NULL THEN
      EXECUTE 'REVOKE INSERT, UPDATE, DELETE ON TABLE public."SanitizedAuditReference" FROM virki_runtime';
      EXECUTE 'GRANT SELECT ON TABLE public."SanitizedAuditReference" TO virki_runtime';
    END IF;
  END IF;

  IF to_regclass('public."AuditLog"') IS NOT NULL THEN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_audit_maintenance') THEN
      EXECUTE 'REVOKE SELECT, INSERT, DELETE ON TABLE public."AuditLog" FROM virki_audit_maintenance';
      EXECUTE 'REVOKE SELECT ("createdAt") ON TABLE public."AuditLog" FROM virki_audit_maintenance';
      EXECUTE 'REVOKE INSERT ("createdAt") ON TABLE public."AuditLog" FROM virki_audit_maintenance';
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_migrator') THEN
      IF to_regnamespace('virki_security') IS NULL THEN
        EXECUTE 'CREATE SCHEMA virki_security AUTHORIZATION virki_migrator';
      END IF;

      IF NOT EXISTS (
        SELECT 1
        FROM pg_namespace AS namespace
        WHERE namespace.nspname = 'virki_security'
          AND namespace.nspowner = (SELECT oid FROM pg_roles WHERE rolname = 'virki_migrator')
      ) THEN
        RAISE EXCEPTION 'virki_security must be owned by virki_migrator';
      END IF;

      EXECUTE $policy$
        CREATE TABLE IF NOT EXISTS virki_security.audit_retention_policy (
          singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
          retention_days integer NOT NULL CHECK (retention_days BETWEEN 1 AND 3650)
        )
      $policy$;
      EXECUTE 'ALTER TABLE virki_security.audit_retention_policy OWNER TO virki_migrator';
      EXECUTE 'INSERT INTO virki_security.audit_retention_policy (singleton, retention_days) VALUES (true, 180) ON CONFLICT (singleton) DO NOTHING';
      EXECUTE 'REVOKE ALL ON TABLE virki_security.audit_retention_policy FROM PUBLIC';
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_runtime') THEN
        EXECUTE 'REVOKE ALL ON TABLE virki_security.audit_retention_policy FROM virki_runtime';
      END IF;
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_runtime_test') THEN
        EXECUTE 'REVOKE ALL ON TABLE virki_security.audit_retention_policy FROM virki_runtime_test';
      END IF;
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_audit_maintenance') THEN
        EXECUTE 'REVOKE ALL ON TABLE virki_security.audit_retention_policy FROM virki_audit_maintenance';
      END IF;

      EXECUTE $timestamp_function$
        CREATE OR REPLACE FUNCTION virki_security.enforce_audit_log_timestamp()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $body$
        BEGIN
          IF current_user IN ('virki_runtime', 'virki_runtime_test') THEN
            NEW."createdAt" := pg_catalog.clock_timestamp();
          END IF;
          RETURN NEW;
        END;
        $body$
      $timestamp_function$;
      EXECUTE 'ALTER FUNCTION virki_security.enforce_audit_log_timestamp() OWNER TO virki_migrator';
      EXECUTE 'REVOKE ALL ON FUNCTION virki_security.enforce_audit_log_timestamp() FROM PUBLIC';
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_runtime') THEN
        EXECUTE 'REVOKE ALL ON FUNCTION virki_security.enforce_audit_log_timestamp() FROM virki_runtime';
      END IF;
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_runtime_test') THEN
        EXECUTE 'REVOKE ALL ON FUNCTION virki_security.enforce_audit_log_timestamp() FROM virki_runtime_test';
      END IF;
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_audit_maintenance') THEN
        EXECUTE 'REVOKE ALL ON FUNCTION virki_security.enforce_audit_log_timestamp() FROM virki_audit_maintenance';
      END IF;
      EXECUTE 'DROP TRIGGER IF EXISTS virki_audit_log_created_at_guard ON public."AuditLog"';
      EXECUTE 'CREATE TRIGGER virki_audit_log_created_at_guard BEFORE INSERT ON public."AuditLog" FOR EACH ROW EXECUTE FUNCTION virki_security.enforce_audit_log_timestamp()';

      EXECUTE 'DROP FUNCTION IF EXISTS virki_security.delete_expired_audit_logs(integer)';
      EXECUTE $function$
        CREATE OR REPLACE FUNCTION virki_security.delete_expired_audit_logs()
        RETURNS TABLE (deleted_count bigint, retention_days integer)
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        AS $body$
        DECLARE
          configured_retention_days integer;
          deleted_rows bigint;
        BEGIN
          SELECT policy.retention_days
          INTO STRICT configured_retention_days
          FROM virki_security.audit_retention_policy AS policy
          WHERE policy.singleton = true;

          DELETE FROM public."AuditLog"
          WHERE "createdAt" < pg_catalog.clock_timestamp() - (configured_retention_days * INTERVAL '1 day');

          GET DIAGNOSTICS deleted_rows = ROW_COUNT;

          IF deleted_rows > 0 THEN
            INSERT INTO public."AuditLog" ("id", "eventType", "result", "resource", "message", "metadata", "schemaVersion", "category", "severity", "action", "reason")
            VALUES (
              pg_catalog.gen_random_uuid()::text,
              'AUTH_AUDIT_LOG_CLEANUP',
              'SUCCESS',
              'audit-log',
              'Expired audit logs cleaned up.',
              pg_catalog.jsonb_build_object(
                'source', 'audit-log-cleanup',
                'deletedCount', deleted_rows,
                'retentionDays', configured_retention_days
              ),
              1,
              'AUTH',
              'INFO',
              'auth.audit.log.cleanup',
              'completed'
            );
          END IF;

          RETURN QUERY SELECT deleted_rows, configured_retention_days;
        END;
        $body$
      $function$;
      EXECUTE 'ALTER FUNCTION virki_security.delete_expired_audit_logs() OWNER TO virki_migrator';
      EXECUTE 'REVOKE ALL ON FUNCTION virki_security.delete_expired_audit_logs() FROM PUBLIC';
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_runtime') THEN
        EXECUTE 'REVOKE ALL ON FUNCTION virki_security.delete_expired_audit_logs() FROM virki_runtime';
      END IF;
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_runtime_test') THEN
        EXECUTE 'REVOKE ALL ON FUNCTION virki_security.delete_expired_audit_logs() FROM virki_runtime_test';
      END IF;
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'virki_audit_maintenance') THEN
        EXECUTE 'GRANT USAGE ON SCHEMA virki_security TO virki_audit_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION virki_security.delete_expired_audit_logs() TO virki_audit_maintenance';
      END IF;
    END IF;
  END IF;
END
$$;
