import { prisma } from "@virki/database";

/** Only the explicit, independently approved staging override may request this gate. */
export function requireScopedEmailWorkerRole(value: string | undefined): boolean {
  if (value === undefined || value === "") return false;
  if (value === "required") return true;
  throw new Error("Invalid email worker role verification setting.");
}

// Check both EFFECTIVE worker privileges and independent PUBLIC ACLs. Even a
// PUBLIC grant on a column allowed to the worker widens access to other roles.
// It does not replace an independent staging acceptance or eliminate DDL
// races between this check and a later SMTP send.
export async function assertScopedEmailWorkerRole(database: typeof prisma = prisma): Promise<void> {
  const rows = await database.$queryRaw<Array<{ allowed: boolean }>>`
    SELECT (
      current_user = 'virki_email_worker'
      AND session_user = 'virki_email_worker'
      AND EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname = current_user
        AND rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole
        AND NOT rolreplication AND NOT rolbypassrls AND NOT rolinherit
      )
      AND NOT EXISTS (
        SELECT 1 FROM pg_auth_members m JOIN pg_roles granted ON granted.oid = m.roleid
        JOIN pg_roles recipient ON recipient.oid = m.member
        WHERE recipient.rolname = current_user OR granted.rolname = current_user
      )
      AND has_table_privilege(current_user, 'public."EmailOutboxMessage"', 'SELECT')
      AND has_table_privilege(current_user, 'public."EmailDeliveryAttempt"', 'SELECT')
      AND has_column_privilege(current_user, 'public."EmailOutboxMessage"', 'status', 'UPDATE')
      AND has_column_privilege(current_user, 'public."EmailDeliveryAttempt"', 'messageId', 'INSERT')
      AND NOT has_database_privilege(current_user, current_database(), 'CREATE')
      AND NOT has_database_privilege(current_user, current_database(), 'TEMPORARY')
      AND NOT has_schema_privilege(current_user, 'public', 'CREATE')
      AND NOT has_table_privilege(current_user, 'public."EmailOutboxMessage"', 'INSERT')
      AND NOT has_table_privilege(current_user, 'public."EmailOutboxMessage"', 'UPDATE')
      AND NOT has_table_privilege(current_user, 'public."EmailOutboxMessage"', 'DELETE')
      AND NOT has_table_privilege(current_user, 'public."EmailOutboxMessage"', 'TRUNCATE')
      AND NOT has_table_privilege(current_user, 'public."EmailOutboxMessage"', 'REFERENCES')
      AND NOT has_table_privilege(current_user, 'public."EmailOutboxMessage"', 'TRIGGER')
      AND NOT has_table_privilege(current_user, 'public."EmailOutboxMessage"', 'MAINTAIN')
      AND NOT has_table_privilege(current_user, 'public."EmailDeliveryAttempt"', 'INSERT')
      AND NOT has_table_privilege(current_user, 'public."EmailDeliveryAttempt"', 'UPDATE')
      AND NOT has_table_privilege(current_user, 'public."EmailDeliveryAttempt"', 'DELETE')
      AND NOT has_table_privilege(current_user, 'public."EmailDeliveryAttempt"', 'TRUNCATE')
      AND NOT has_table_privilege(current_user, 'public."EmailDeliveryAttempt"', 'REFERENCES')
      AND NOT has_table_privilege(current_user, 'public."EmailDeliveryAttempt"', 'TRIGGER')
      AND NOT has_table_privilege(current_user, 'public."EmailDeliveryAttempt"', 'MAINTAIN')
      AND NOT EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl, acldefault('r',c.relowner))) acl
        WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f')
          AND acl.grantee=0
      )
      AND NOT EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        JOIN pg_attribute a ON a.attrelid=c.oid
        CROSS JOIN LATERAL aclexplode(a.attacl) acl
        WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f')
          AND a.attnum>0 AND NOT a.attisdropped AND acl.grantee=0
      )
      AND NOT EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f')
          AND c.relname NOT IN ('EmailOutboxMessage','EmailDeliveryAttempt')
          AND (has_table_privilege(current_user,c.oid,'SELECT')
            OR has_table_privilege(current_user,c.oid,'INSERT')
            OR has_table_privilege(current_user,c.oid,'UPDATE')
            OR has_table_privilege(current_user,c.oid,'DELETE')
            OR has_table_privilege(current_user,c.oid,'TRUNCATE')
            OR has_table_privilege(current_user,c.oid,'REFERENCES')
            OR has_table_privilege(current_user,c.oid,'TRIGGER')
            OR has_table_privilege(current_user,c.oid,'MAINTAIN'))
      )
      AND NOT EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        JOIN pg_attribute a ON a.attrelid=c.oid
        WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f')
          AND a.attnum>0 AND NOT a.attisdropped AND (
            (c.relname NOT IN ('EmailOutboxMessage','EmailDeliveryAttempt')
              AND (has_column_privilege(current_user,c.oid,a.attname,'SELECT')
                OR has_column_privilege(current_user,c.oid,a.attname,'UPDATE')
                OR has_column_privilege(current_user,c.oid,a.attname,'INSERT')
                OR has_column_privilege(current_user,c.oid,a.attname,'REFERENCES')))
            OR (c.relname='EmailOutboxMessage'
              AND (has_column_privilege(current_user,c.oid,a.attname,'INSERT')
                OR has_column_privilege(current_user,c.oid,a.attname,'REFERENCES')
                OR (a.attname NOT IN ('status','attemptCount','availableAt','sentAt',
                  'terminalFailedAt','processingLeaseExpiresAt','pendingSmtpHeaderMessageId','updatedAt')
                  AND has_column_privilege(current_user,c.oid,a.attname,'UPDATE'))))
            OR (c.relname='EmailDeliveryAttempt'
              AND (has_column_privilege(current_user,c.oid,a.attname,'UPDATE')
                OR has_column_privilege(current_user,c.oid,a.attname,'REFERENCES')
                OR (a.attname NOT IN ('id','messageId','attempt','status','errorCode',
                  'smtpHeaderMessageId','attemptedAt')
                  AND has_column_privilege(current_user,c.oid,a.attname,'INSERT'))))
          )
      )
      AND NOT EXISTS (
        SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='public' AND has_function_privilege(current_user,p.oid,'EXECUTE')
      )
      AND NOT EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND c.relkind='S'
          AND (has_sequence_privilege(current_user,c.oid,'USAGE')
            OR has_sequence_privilege(current_user,c.oid,'SELECT')
            OR has_sequence_privilege(current_user,c.oid,'UPDATE'))
      )
      AND NOT EXISTS (
        SELECT 1 FROM pg_namespace n
        WHERE n.nspname NOT IN ('public','information_schema')
          AND left(n.nspname,3)<>'pg_'
          AND (has_schema_privilege(current_user,n.oid,'USAGE')
            OR has_schema_privilege(current_user,n.oid,'CREATE'))
      )
      AND NOT EXISTS (
        SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname NOT IN ('public','information_schema')
          AND left(n.nspname,3)<>'pg_'
          AND has_function_privilege(current_user,p.oid,'EXECUTE')
      )
      AND NOT EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname NOT IN ('public','information_schema')
          AND left(n.nspname,3)<>'pg_'
          AND ((c.relkind IN ('r','p','v','m','f')
            AND (has_table_privilege(current_user,c.oid,'SELECT')
              OR has_table_privilege(current_user,c.oid,'INSERT')
              OR has_table_privilege(current_user,c.oid,'UPDATE')
              OR has_table_privilege(current_user,c.oid,'DELETE')
              OR has_table_privilege(current_user,c.oid,'TRUNCATE')
              OR has_table_privilege(current_user,c.oid,'REFERENCES')
              OR has_table_privilege(current_user,c.oid,'TRIGGER')
              OR has_table_privilege(current_user,c.oid,'MAINTAIN')))
          OR (c.relkind='S' AND (has_sequence_privilege(current_user,c.oid,'USAGE')
            OR has_sequence_privilege(current_user,c.oid,'SELECT')
            OR has_sequence_privilege(current_user,c.oid,'UPDATE'))))
      )
      AND NOT EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        JOIN pg_attribute a ON a.attrelid=c.oid
        WHERE n.nspname NOT IN ('public','information_schema')
          AND left(n.nspname,3)<>'pg_' AND c.relkind IN ('r','p','v','m','f')
          AND a.attnum>0 AND NOT a.attisdropped
          AND (has_column_privilege(current_user,c.oid,a.attname,'SELECT')
            OR has_column_privilege(current_user,c.oid,a.attname,'INSERT')
            OR has_column_privilege(current_user,c.oid,a.attname,'UPDATE')
            OR has_column_privilege(current_user,c.oid,a.attname,'REFERENCES'))
      )
    ) AS allowed
  `;
  if (rows.length !== 1 || rows[0]?.allowed !== true) {
    throw new Error("Email worker database role permissions are not scoped for staging.");
  }
}
