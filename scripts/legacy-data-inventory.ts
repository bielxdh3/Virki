import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { isIP } from "node:net";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { normalizeEmail } from "@virki/auth";
import { PrismaClient } from "@virki/database";

export type InventoryArguments = {
  expectedHost: string;
  expectedPort: number;
  expectedDatabase: string;
  expectedServerAddress: string;
  expectedServerPort: number;
};
export type EmailInventoryRow = { email: string; emailNormalized: string | null };
export type InventoryMigrationRow = { migrationName: string; checksum: string; finishedAt: Date | null; rolledBackAt: Date | null };
export type ExpectedInventoryMigration = { name: string; checksum: string };
export type InventoryCanonicalEmailIndex = {
  columnName: string;
  isUnique: boolean;
  isValid: boolean;
  isReady: boolean;
  keyColumns: number;
  totalColumns: number;
  noPredicate: boolean;
  noExpressions: boolean;
};
export type InventoryPrivilegeSnapshot = {
  relations: Array<{
    name: string;
    kind: string;
    canSelect: boolean;
    hasAnyPrivilege: boolean;
    hasWritePrivilege: boolean;
    hasAnyColumnPrivilege: boolean;
    hasColumnWritePrivilege: boolean;
    rowSecurityEnabled: boolean;
    ownedByCurrentRole: boolean;
  }>;
  sequences: Array<{ name: string; hasAnyPrivilege: boolean; ownedByCurrentRole: boolean }>;
  functions: Array<{ name: string; canExecute: boolean; ownedByCurrentRole: boolean }>;
  schemas: Array<{ name: string; canUse: boolean; canCreate: boolean; ownedByCurrentRole: boolean }>;
  database: { canCreate: boolean; canCreateTemporaryObjects: boolean; ownedByCurrentRole: boolean };
  hasUnsafeDefaultPrivileges: boolean;
  ownsAnyDatabaseObject: boolean;
};

const REQUIRED_COLUMNS: Record<string, string[]> = {
  User: ["id", "email", "emailNormalized", "isActive", "accountStatus", "role"],
  Session: ["id", "userId", "revokedAt", "expiresAt"],
  SecurityElevation: ["userId", "sessionId", "scope", "status", "manualUntilRevoked", "expiresAt"],
  UserProjectGrant: ["grantedByUserId"],
  AccountRecoveryRequest: ["userId", "reviewedByUserId"],
  EmailOutboxMessage: ["status", "processingLeaseExpiresAt", "sentAt", "terminalFailedAt"],
  ProjectConnection: ["createdByUserId"],
  _prisma_migrations: ["migration_name", "finished_at", "rolled_back_at"]
};

const INVENTORY_TABLES = Object.keys(REQUIRED_COLUMNS);
const INVENTORY_RELATION_KINDS = new Set(["r", "p"]);

export function validateInventoryPrivilegeSnapshot(snapshot: InventoryPrivilegeSnapshot): true {
  const fail = () => { throw new Error("Database privilege boundary does not match the read-only inventory contract."); };
  const allowedTables = new Set(INVENTORY_TABLES);

  for (const tableName of INVENTORY_TABLES) {
    const matches = snapshot.relations.filter((relation) => relation.name === tableName);
    if (matches.length !== 1) fail();
    const [table] = matches;
    if (!table || !INVENTORY_RELATION_KINDS.has(table.kind) || !table.canSelect || table.hasWritePrivilege || table.hasColumnWritePrivilege || table.rowSecurityEnabled || table.ownedByCurrentRole) {
      fail();
    }
  }

  if (snapshot.relations.some((relation) => !allowedTables.has(relation.name) && (relation.hasAnyPrivilege || relation.hasAnyColumnPrivilege || relation.ownedByCurrentRole))) {
    fail();
  }
  if (snapshot.sequences.some((sequence) => sequence.hasAnyPrivilege || sequence.ownedByCurrentRole)) fail();
  if (snapshot.functions.some((routine) => routine.canExecute || routine.ownedByCurrentRole)) fail();

  const publicSchema = snapshot.schemas.filter((schema) => schema.name === "public");
  const informationSchema = snapshot.schemas.filter((schema) => schema.name === "information_schema");
  if (publicSchema.length !== 1 || !publicSchema[0]?.canUse || publicSchema[0].canCreate || publicSchema[0].ownedByCurrentRole) fail();
  if (informationSchema.length !== 1 || !informationSchema[0]?.canUse || informationSchema[0].canCreate || informationSchema[0].ownedByCurrentRole) fail();
  if (snapshot.schemas.some((schema) => !["public", "information_schema"].includes(schema.name) && (schema.canUse || schema.canCreate || schema.ownedByCurrentRole))) fail();

  if (snapshot.database.canCreate || snapshot.database.canCreateTemporaryObjects || snapshot.database.ownedByCurrentRole || snapshot.hasUnsafeDefaultPrivileges || snapshot.ownsAnyDatabaseObject) fail();
  return true;
}

export function parseInventoryArguments(args: string[]): InventoryArguments {
  const values = new Map<string, string>();
  let confirmed = false;
  for (let index = 0; index < args.length; index += 1) {
    const flag = args[index];
    if (flag === "--confirm-target") {
      confirmed = true;
      continue;
    }
    if (flag !== "--expected-host" && flag !== "--expected-port" && flag !== "--expected-database" && flag !== "--expected-server-address" && flag !== "--expected-server-port") {
      throw new Error("Inventory requires an explicit target identity.");
    }
    const value = args[index + 1];
    if (!value || value.startsWith("--") || values.has(flag)) {
      throw new Error("Inventory requires an explicit target identity.");
    }
    values.set(flag, value);
    index += 1;
  }

  const expectedHost = values.get("--expected-host");
  const configuredPort = values.get("--expected-port");
  const expectedDatabase = values.get("--expected-database");
  const expectedServerAddress = values.get("--expected-server-address");
  const configuredServerPort = values.get("--expected-server-port");
  const validPort = (value: string | undefined) =>
    Boolean(value && /^[1-9][0-9]{0,4}$/u.test(value) && Number(value) <= 65535);
  if (!confirmed || !expectedHost || !validPort(configuredPort) || !expectedDatabase || !expectedServerAddress || !validPort(configuredServerPort) || isIP(expectedServerAddress) === 0) {
    throw new Error("Inventory requires an explicit target identity and --confirm-target.");
  }
  return { expectedHost, expectedPort: Number(configuredPort), expectedDatabase, expectedServerAddress, expectedServerPort: Number(configuredServerPort) };
}

export function validateInventoryTarget(databaseUrl: string, expectedHost: string, expectedDatabase: string, expectedPort: number): true {
  try {
    const configured = new URL(databaseUrl);
    const hostMatches = configured.protocol === "postgres:" || configured.protocol === "postgresql:"
      ? normalizeHost(configured.hostname) === normalizeHost(expectedHost)
      : false;
    const configuredDatabase = decodeURIComponent(configured.pathname.replace(/^\/+/, ""));
    const configuredPort = configured.port ? Number(configured.port) : 5432;
    if (!hostMatches || configuredDatabase !== expectedDatabase || configuredPort !== expectedPort) throw new Error("target");
    return true;
  } catch {
    throw new Error("Inventory target does not match the independently supplied host and database.");
  }
}

export function validateConnectedServerAddress(actualAddress: string | null, expectedAddress: string): true {
  if (!actualAddress || isIP(actualAddress) === 0 || isIP(expectedAddress) === 0 || actualAddress !== expectedAddress) {
    throw new Error("Connected PostgreSQL server does not match the independently supplied address.");
  }
  return true;
}

export function validateConnectedServerPort(actualPort: number | null, expectedPort: number): true {
  if (!Number.isInteger(actualPort) || actualPort === null || actualPort < 1 || actualPort > 65535 || actualPort !== expectedPort) {
    throw new Error("Connected PostgreSQL server port does not match the independently supplied value.");
  }
  return true;
}

export function summarizeEmailInventory(rows: EmailInventoryRow[]) {
  let normalizedNull = 0;
  let normalizedBlank = 0;
  let normalizationMismatch = 0;
  const canonicalCounts = new Map<string, number>();

  for (const row of rows) {
    const canonical = normalizeEmail(row.email);
    canonicalCounts.set(canonical, (canonicalCounts.get(canonical) ?? 0) + 1);
    if (row.emailNormalized === null) {
      normalizedNull += 1;
    } else {
      if (row.emailNormalized.trim().length === 0) normalizedBlank += 1;
      if (row.emailNormalized !== canonical) normalizationMismatch += 1;
    }
  }

  const collisionGroups = [...canonicalCounts.values()].filter((count) => count > 1);
  return {
    totalUsers: rows.length,
    normalizedNull,
    normalizedBlank,
    normalizationMismatch,
    collisionGroupCount: collisionGroups.length,
    collisionMemberCount: collisionGroups.reduce((sum, count) => sum + count, 0)
  };
}

export function validateInventoryMigrationSet(
  migrations: InventoryMigrationRow[],
  expectedMigrations: ExpectedInventoryMigration[]
): number {
  const fail = () => { throw new Error("Database migration state does not match the current source."); };
  const expectedByName = new Map(expectedMigrations.map(({ name, checksum }) => [name, checksum]));
  if (expectedByName.size === 0 || expectedByName.size !== expectedMigrations.length) fail();

  const completedNames = new Set<string>();
  for (const migration of migrations) {
    const expectedChecksum = expectedByName.get(migration.migrationName);
    if (!expectedChecksum || (migration.finishedAt && migration.rolledBackAt)) fail();
    if (migration.rolledBackAt) continue; // A resolved failed attempt may precede a successful retry.
    if (!migration.finishedAt || migration.checksum !== expectedChecksum || completedNames.has(migration.migrationName)) fail();
    completedNames.add(migration.migrationName);
  }
  if (completedNames.size !== expectedByName.size) fail();
  return completedNames.size;
}

export function hashInventoryMigrationSql(bytes: Uint8Array): string {
  const buffer = Buffer.from(bytes);
  const decoded = buffer.toString("utf8");
  // Git stores the reviewed migration.sql files with LF. A Windows checkout may
  // convert only the line endings to CRLF; hash the reviewed LF representation.
  if (!Buffer.from(decoded, "utf8").equals(buffer)) {
    throw new Error("Migration SQL bytes cannot be validated safely.");
  }
  const normalized = decoded.replace(/\r\n/gu, "\n");
  if (normalized.includes("\r")) {
    throw new Error("Migration SQL line endings cannot be validated safely.");
  }
  return createHash("sha256").update(normalized, "utf8").digest("hex");
}

export function validateInventoryCanonicalEmailIndex(indexes: InventoryCanonicalEmailIndex[]): true {
  const [index] = indexes;
  if (indexes.length !== 1 || !index || index.columnName !== "emailNormalized" ||
      !index.isUnique || !index.isValid || !index.isReady ||
      index.keyColumns !== 1 || index.totalColumns !== 1 || !index.noPredicate || !index.noExpressions) {
    throw new Error("Database schema does not match the inventory contract.");
  }
  return true;
}

function normalizeHost(host: string): string {
  return host.toLowerCase().replace(/^\[|\]$/gu, "").replace(/\.$/u, "");
}

function toJsonCounts(record: Record<string, unknown>): Record<string, string | number | boolean | null> {
  return Object.fromEntries(Object.entries(record).map(([key, value]) => [key, typeof value === "bigint" ? value.toString() : value as string | number | boolean | null]));
}

type InventorySqlClient = Pick<PrismaClient, "$queryRaw">;

export async function inspectInventoryPrivilegeSnapshot(transaction: InventorySqlClient): Promise<InventoryPrivilegeSnapshot> {
  const relations = await transaction.$queryRaw<InventoryPrivilegeSnapshot["relations"]>`
    SELECT c.relname AS "name", c.relkind::text AS "kind",
      has_table_privilege(current_user, c.oid, 'SELECT') AS "canSelect",
      (has_table_privilege(current_user, c.oid, 'SELECT') OR
       has_table_privilege(current_user, c.oid, 'INSERT') OR
       has_table_privilege(current_user, c.oid, 'UPDATE') OR
       has_table_privilege(current_user, c.oid, 'DELETE') OR
       has_table_privilege(current_user, c.oid, 'TRUNCATE') OR
       has_table_privilege(current_user, c.oid, 'REFERENCES') OR
       has_table_privilege(current_user, c.oid, 'TRIGGER') OR
       has_table_privilege(current_user, c.oid, 'MAINTAIN')) AS "hasAnyPrivilege",
      (has_table_privilege(current_user, c.oid, 'INSERT') OR
       has_table_privilege(current_user, c.oid, 'UPDATE') OR
       has_table_privilege(current_user, c.oid, 'DELETE') OR
       has_table_privilege(current_user, c.oid, 'TRUNCATE') OR
       has_table_privilege(current_user, c.oid, 'REFERENCES') OR
       has_table_privilege(current_user, c.oid, 'TRIGGER') OR
       has_table_privilege(current_user, c.oid, 'MAINTAIN')) AS "hasWritePrivilege",
      (has_any_column_privilege(current_user, c.oid, 'SELECT') OR
       has_any_column_privilege(current_user, c.oid, 'INSERT') OR
       has_any_column_privilege(current_user, c.oid, 'UPDATE') OR
       has_any_column_privilege(current_user, c.oid, 'REFERENCES')) AS "hasAnyColumnPrivilege",
      (has_any_column_privilege(current_user, c.oid, 'INSERT') OR
       has_any_column_privilege(current_user, c.oid, 'UPDATE') OR
       has_any_column_privilege(current_user, c.oid, 'REFERENCES')) AS "hasColumnWritePrivilege",
      (c.relrowsecurity OR c.relforcerowsecurity) AS "rowSecurityEnabled",
      c.relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user) AS "ownedByCurrentRole"
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
  `;
  const sequences = await transaction.$queryRaw<InventoryPrivilegeSnapshot["sequences"]>`
    SELECT c.relname AS "name",
      (has_sequence_privilege(current_user, c.oid, 'USAGE') OR
       has_sequence_privilege(current_user, c.oid, 'SELECT') OR
       has_sequence_privilege(current_user, c.oid, 'UPDATE')) AS "hasAnyPrivilege",
      c.relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user) AS "ownedByCurrentRole"
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind = 'S'
  `;
  const functions = await transaction.$queryRaw<InventoryPrivilegeSnapshot["functions"]>`
    SELECT p.oid::regprocedure::text AS "name",
      has_function_privilege(current_user, p.oid, 'EXECUTE') AS "canExecute",
      p.proowner = (SELECT oid FROM pg_roles WHERE rolname = current_user) AS "ownedByCurrentRole"
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public'
  `;
  const schemas = await transaction.$queryRaw<InventoryPrivilegeSnapshot["schemas"]>`
    SELECT n.nspname AS "name",
      has_schema_privilege(current_user, n.oid, 'USAGE') AS "canUse",
      has_schema_privilege(current_user, n.oid, 'CREATE') AS "canCreate",
      n.nspowner = (SELECT oid FROM pg_roles WHERE rolname = current_user) AS "ownedByCurrentRole"
    FROM pg_namespace n
    WHERE left(n.nspname, 3) <> 'pg_'
  `;
  const [database] = await transaction.$queryRaw<Array<InventoryPrivilegeSnapshot["database"]>>`
    SELECT has_database_privilege(current_user, current_database(), 'CREATE') AS "canCreate",
      has_database_privilege(current_user, current_database(), 'TEMPORARY') AS "canCreateTemporaryObjects",
      (SELECT d.datdba = r.oid FROM pg_database d CROSS JOIN pg_roles r WHERE d.datname = current_database() AND r.rolname = current_user) AS "ownedByCurrentRole"
  `;
  const [otherPrivileges] = await transaction.$queryRaw<Array<{
    hasUnsafeDefaultPrivileges: boolean;
    ownsAnyDatabaseObject: boolean;
  }>>`
    SELECT
      EXISTS (
        SELECT 1
        FROM pg_default_acl d
        CROSS JOIN LATERAL aclexplode(d.defaclacl) acl
        WHERE d.defaclobjtype IN ('r', 'S', 'f')
          AND (d.defaclnamespace = 0 OR d.defaclnamespace = 'public'::regnamespace)
          AND acl.grantee IN (0, (SELECT oid FROM pg_roles WHERE rolname = current_user))
      ) AS "hasUnsafeDefaultPrivileges",
      EXISTS (
        SELECT 1
        FROM pg_shdepend dependency
        WHERE dependency.dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
          AND dependency.refclassid = 'pg_authid'::regclass
          AND dependency.refobjid = (SELECT oid FROM pg_roles WHERE rolname = current_user)
          AND dependency.deptype = 'o'
      ) AS "ownsAnyDatabaseObject"
  `;
  if (!database || !otherPrivileges) throw new Error("Database privilege boundary could not be verified.");
  return {
    relations,
    sequences,
    functions,
    schemas,
    database,
    hasUnsafeDefaultPrivileges: otherPrivileges.hasUnsafeDefaultPrivileges,
    ownsAnyDatabaseObject: otherPrivileges.ownsAnyDatabaseObject
  };
}

async function runInventory(expected: InventoryArguments) {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) throw new Error("DATABASE_URL is required.");
  validateInventoryTarget(databaseUrl, expected.expectedHost, expected.expectedDatabase, expected.expectedPort);

  const client = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
  try {
    return await client.$transaction(async (transaction) => {
      await transaction.$executeRawUnsafe("SET TRANSACTION READ ONLY");
      const [identity] = await transaction.$queryRaw<Array<{
        databaseName: string;
        serverAddress: string | null;
        serverPort: number | null;
        schemaName: string | null;
        serverVersion: number;
        transactionReadOnly: string;
      }>>`
        SELECT current_database() AS "databaseName", inet_server_addr()::text AS "serverAddress",
          inet_server_port() AS "serverPort", current_schema() AS "schemaName",
          current_setting('server_version_num')::integer AS "serverVersion",
          current_setting('transaction_read_only') AS "transactionReadOnly"
      `;
      if (!identity || identity.databaseName !== expected.expectedDatabase || identity.schemaName !== "public" || Math.floor(identity.serverVersion / 10_000) !== 17 || identity.transactionReadOnly !== "on") {
        throw new Error("Database identity or read-only transaction preflight failed.");
      }
      validateConnectedServerAddress(identity.serverAddress, expected.expectedServerAddress);
      validateConnectedServerPort(identity.serverPort, expected.expectedServerPort);

      const [role] = await transaction.$queryRaw<Array<{
        isSuperuser: boolean;
        canCreateDatabase: boolean;
        canCreateRole: boolean;
        canReplicate: boolean;
        bypassesRowSecurity: boolean;
        hasRoleMembership: boolean;
      }>>`
        SELECT r.rolsuper AS "isSuperuser", r.rolcreatedb AS "canCreateDatabase",
          r.rolcreaterole AS "canCreateRole", r.rolreplication AS "canReplicate",
          r.rolbypassrls AS "bypassesRowSecurity",
          EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member = r.oid) AS "hasRoleMembership"
        FROM pg_roles r WHERE r.rolname = current_user
      `;
      if (!role || role.isSuperuser || role.canCreateDatabase || role.canCreateRole || role.canReplicate || role.bypassesRowSecurity || role.hasRoleMembership) {
        throw new Error("Database role is not a dedicated read-only principal.");
      }

      const privilegeSnapshot = await inspectInventoryPrivilegeSnapshot(transaction);
      validateInventoryPrivilegeSnapshot(privilegeSnapshot);

      const columns = await transaction.$queryRaw<Array<{ tableName: string; columnName: string }>>`
        SELECT table_name AS "tableName", column_name AS "columnName"
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = ANY(ARRAY['User','Session','SecurityElevation','UserProjectGrant','AccountRecoveryRequest','EmailOutboxMessage','ProjectConnection','_prisma_migrations']::text[])
      `;
      const columnSet = new Set(columns.map(({ tableName, columnName }) => `${tableName}.${columnName}`));
      for (const [table, required] of Object.entries(REQUIRED_COLUMNS)) {
        if (required.some((column) => !columnSet.has(`${table}.${column}`))) {
          throw new Error("Database schema does not match the inventory contract.");
        }
      }

      const canonicalEmailIndexes = await transaction.$queryRaw<InventoryCanonicalEmailIndex[]>`
        SELECT a.attname AS "columnName", i.indisunique AS "isUnique",
          i.indisvalid AS "isValid", i.indisready AS "isReady",
          i.indnkeyatts::integer AS "keyColumns", i.indnatts::integer AS "totalColumns",
          (i.indpred IS NULL) AS "noPredicate", (i.indexprs IS NULL) AS "noExpressions"
        FROM pg_index i
        JOIN pg_class t ON t.oid = i.indrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        JOIN pg_class idx ON idx.oid = i.indexrelid
        LEFT JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = i.indkey[0]
        WHERE n.nspname = 'public' AND t.relname = 'User' AND idx.relname = 'User_emailNormalized_key'
      `;
      validateInventoryCanonicalEmailIndex(canonicalEmailIndexes);

      const migrations = await transaction.$queryRaw<InventoryMigrationRow[]>`
        SELECT migration_name AS "migrationName", checksum, finished_at AS "finishedAt", rolled_back_at AS "rolledBackAt"
        FROM public."_prisma_migrations"
      `;
      const migrationDirectory = path.join(process.cwd(), "packages", "database", "prisma", "migrations");
      const expectedMigrations = readdirSync(migrationDirectory, { withFileTypes: true })
        .filter((entry) => entry.isDirectory())
        .map((entry) => ({
          name: entry.name,
          checksum: hashInventoryMigrationSql(readFileSync(path.join(migrationDirectory, entry.name, "migration.sql")))
        }));
      const completedMigrationCount = validateInventoryMigrationSet(migrations, expectedMigrations);

      const elevations = await transaction.$queryRaw<Array<Record<string, unknown>> >`
        SELECT
          count(*) FILTER (WHERE s.id IS NULL) AS "missingSession",
          count(*) FILTER (WHERE s.id IS NOT NULL AND s."userId" <> e."userId") AS "ownerMismatch",
          count(*) FILTER (WHERE e.status::text = 'ACTIVE' AND e."manualUntilRevoked" AND (s.id IS NULL OR s."revokedAt" IS NOT NULL OR s."expiresAt" <= now())) AS "activeManualWithInvalidSession"
        FROM public."SecurityElevation" e
        LEFT JOIN public."Session" s ON s.id = e."sessionId"
      `;
      const [elevationDuplicates] = await transaction.$queryRaw<Array<{ duplicateTupleGroups: bigint; duplicateActiveGroups: bigint }>>`
        SELECT
          (SELECT count(*) FROM (SELECT 1 FROM public."SecurityElevation" GROUP BY "userId", "sessionId", scope HAVING count(*) > 1) all_duplicates) AS "duplicateTupleGroups",
          (SELECT count(*) FROM (SELECT 1 FROM public."SecurityElevation" WHERE status::text = 'ACTIVE' GROUP BY "userId", "sessionId", scope HAVING count(*) > 1) active_duplicates) AS "duplicateActiveGroups"
      `;

      const emailRows = await transaction.$queryRaw<EmailInventoryRow[]>`
        SELECT email, "emailNormalized" FROM public."User"
      `;
      const emailInventory = summarizeEmailInventory(emailRows);
      const [accountStates] = await transaction.$queryRaw<Array<Record<string, unknown>> >`
        SELECT
          count(*) FILTER (WHERE "accountStatus"::text = 'ACTIVE' AND "isActive") AS "activeStatusWithActiveFlag",
          count(*) FILTER (WHERE "accountStatus"::text = 'ACTIVE' AND NOT "isActive") AS "activeStatusWithInactiveFlag",
          count(*) FILTER (WHERE "accountStatus"::text = 'INACTIVE' AND "isActive") AS "inactiveStatusWithActiveFlag",
          count(*) FILTER (WHERE "accountStatus"::text = 'INACTIVE' AND NOT "isActive") AS "inactiveStatusWithInactiveFlag",
          count(*) FILTER (WHERE "accountStatus"::text = 'BLOCKED' AND "isActive") AS "blockedStatusWithActiveFlag",
          count(*) FILTER (WHERE "accountStatus"::text = 'BLOCKED' AND NOT "isActive") AS "blockedStatusWithInactiveFlag",
          count(*) FILTER (WHERE "accountStatus"::text = 'PENDING_ACTIVATION' AND "isActive") AS "pendingStatusWithActiveFlag",
          count(*) FILTER (WHERE "accountStatus"::text = 'PENDING_ACTIVATION' AND NOT "isActive") AS "pendingStatusWithInactiveFlag"
        FROM public."User"
      `;
      const [outbox] = await transaction.$queryRaw<Array<Record<string, unknown>> >`
        SELECT
          count(*) FILTER (WHERE status::text = 'PROCESSING' AND "processingLeaseExpiresAt" IS NULL) AS "processingWithoutLease",
          count(*) FILTER (WHERE status::text = 'PROCESSING' AND "processingLeaseExpiresAt" <= now()) AS "expiredProcessingLease",
          count(*) FILTER (WHERE status::text <> 'PROCESSING' AND "processingLeaseExpiresAt" IS NOT NULL) AS "strayLease",
          count(*) FILTER (WHERE status::text = 'SENT' AND "sentAt" IS NULL) AS "sentWithoutTimestamp",
          count(*) FILTER (WHERE status::text = 'TERMINAL_FAILURE' AND "terminalFailedAt" IS NULL) AS "terminalFailureWithoutTimestamp",
          count(*) FILTER (WHERE status::text <> 'SENT' AND "sentAt" IS NOT NULL) AS "sentTimestampOnOtherStatus"
        FROM public."EmailOutboxMessage"
      `;
      const [grantAndReview] = await transaction.$queryRaw<Array<Record<string, unknown>> >`
        SELECT
          (SELECT count(*) FROM public."UserProjectGrant" g LEFT JOIN public."User" u ON u.id = g."grantedByUserId" WHERE g."grantedByUserId" IS NOT NULL AND u.id IS NULL) AS "orphanedGrantors",
          (SELECT count(*) FROM public."AccountRecoveryRequest" r WHERE r."reviewedByUserId" = r."userId") AS "selfReviewedRequests",
          (SELECT count(*) FROM public."AccountRecoveryRequest" r LEFT JOIN public."User" u ON u.id = r."reviewedByUserId" WHERE r."reviewedByUserId" IS NOT NULL AND u.id IS NULL) AS "missingReviewers"
      `;
      const workload = await transaction.$queryRaw<Array<{ tableName: string; estimatedRows: bigint; totalBytes: bigint; sequentialScans: bigint; indexScans: bigint; inserted: bigint; updated: bigint; deleted: bigint }>>`
        SELECT c.relname AS "tableName", greatest(c.reltuples::bigint, 0) AS "estimatedRows",
          pg_total_relation_size(c.oid) AS "totalBytes",
          coalesce(s.seq_scan, 0)::bigint AS "sequentialScans", coalesce(s.idx_scan, 0)::bigint AS "indexScans",
          coalesce(s.n_tup_ins, 0)::bigint AS "inserted", coalesce(s.n_tup_upd, 0)::bigint AS "updated", coalesce(s.n_tup_del, 0)::bigint AS "deleted"
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
        WHERE n.nspname = 'public' AND c.relname = ANY(ARRAY['User','Session','SecurityElevation','UserProjectGrant','AccountRecoveryRequest','EmailOutboxMessage','ProjectConnection']::text[])
        ORDER BY c.relname
      `;

      return {
        schemaVersion: 1,
        preflight: {
          configuredEndpointMatched: true,
          databaseMatched: true,
          serverAddressMatched: true,
          endpointPortMatched: true,
          serverPortMatched: true,
          postgresMajor: 17,
          schemaMatched: true,
          canonicalEmailUniquenessMatched: true,
          migrationsMatched: true,
          readOnlyTransaction: true,
          dedicatedReadOnlyRole: true,
          appliedMigrationCount: completedMigrationCount
        },
        counts: {
          elevation: { ...toJsonCounts(elevations[0] ?? {}), ...toJsonCounts(elevationDuplicates as unknown as Record<string, unknown>) },
          accountEmails: emailInventory,
          accountStates: toJsonCounts(accountStates ?? {}),
          outbox: toJsonCounts(outbox ?? {}),
          grantAndReview: toJsonCounts(grantAndReview ?? {}),
          workload: workload.map((row) => ({
            table: row.tableName,
            estimatedRows: row.estimatedRows.toString(),
            totalBytes: row.totalBytes.toString(),
            sequentialScans: row.sequentialScans.toString(),
            indexScans: row.indexScans.toString(),
            inserted: row.inserted.toString(),
            updated: row.updated.toString(),
            deleted: row.deleted.toString()
          }))
        }
      };
    }, { maxWait: 10_000, timeout: 120_000 });
  } finally {
    await client.$disconnect();
  }
}

async function main() {
  const expected = parseInventoryArguments(process.argv.slice(2));
  const result = await runInventory(expected);
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  void main().catch(() => {
    process.stderr.write("Legacy inventory failed closed; no row-level output was emitted.\n");
    process.exitCode = 1;
  });
}
