// Local physical HOL/CAS admission. No GitHub-hosted runner impersonation.
// The physical launcher accepts only the fixed, signed Windows Docker Desktop
// Linux pipe and a brand-new owner-labelled PostgreSQL 17 container.
export const HOL_IMAGE_DIGEST = "sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24";
export const HOL_IMAGE = `postgres:17-alpine@${HOL_IMAGE_DIGEST}`;
export const HOL_OWNER_LABEL = "org.virki.email-hol-disposable-owner";
export const HOL_KIND_LABEL = "org.virki.email-hol-disposable-kind";
export const HOL_KIND = "exclusive-test";
const ID = /^sha256:[a-f0-9]{64}$/u;
const CID = /^[a-f0-9]{64}$/u;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const DB = /^virki_email_worker_hol_[a-f0-9]{12}$/u;
const SYSTEM_KEYS = Object.freeze([
  "PATH", "Path", "SystemRoot", "WINDIR", "HOME", "USERPROFILE",
  "APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL"
]);

export function assertLocalHolHost({ platform, source }) {
  if (platform !== "win32") throw new Error("Local HOL proof requires Windows Docker Desktop, not a CI runner.");
  if (source.NODE_ENV === "production" || source.CI === "true") {
    throw new Error("Local HOL refuses production and CI environments.");
  }
  for (const key of Object.keys(source)) {
    if (/^(?:DOCKER_|VIRKI_|CLOUDFLARE_|GITHUB_|ACTIONS_|RUNNER_)/iu.test(key) ||
        /^(?:DATABASE_URL|MIGRATION_DATABASE_URL|NODE_OPTIONS|NODE_PATH|GH_TOKEN)$/iu.test(key)) {
      if (source[key] !== undefined && source[key] !== "") {
        throw new Error(`Local HOL refuses inherited Docker overrides, database, mail or runtime secrets (${key}).`);
      }
    }
  }
}

export function localHolSystemEnvironment(source) {
  return Object.fromEntries(SYSTEM_KEYS.filter((key) =>
    typeof source[key] === "string" && source[key].length > 0).map((key) => [key, source[key]]));
}

export function localHolTestEnvironment({ source, databaseUrl, migrationUrl, secret }) {
  if (typeof secret !== "function" || typeof databaseUrl !== "string" || typeof migrationUrl !== "string") {
    throw new Error("Local HOL disposable connection and secret generator required.");
  }
  const db = new URL(databaseUrl);
  const migration = new URL(migrationUrl);
  if (!["postgres:", "postgresql:"].includes(db.protocol) || db.hostname !== "127.0.0.1" ||
      db.username !== "virki_runtime_test" || !DB.test(db.pathname.slice(1)) ||
      !["postgres:", "postgresql:"].includes(migration.protocol) || migration.hostname !== "127.0.0.1" ||
      migration.username !== "virki_migrator" || migration.pathname !== db.pathname ||
      migration.port !== db.port || db.search !== "?schema=public" ||
      migration.search !== "?schema=public" || db.hash || migration.hash ||
      db.password.length < 32 || migration.password.length < 32 || db.password === migration.password) {
    throw new Error("Local HOL requires fresh same-target loopback runtime/migrator role isolation.");
  }
  const keys = [secret(), secret(), secret()];
  if (keys.some((key) => !/^[a-f0-9]{64}$/u.test(key)) || new Set(keys).size !== 3) {
    throw new Error("Local HOL requires three independent ephemeral encryption keys.");
  }
  return {
    ...localHolSystemEnvironment(source),
    NODE_ENV: "test", VIRKI_INTEGRATION_ENABLED: "true",
    VIRKI_CORE_TEST_DATABASE_CONFIRM: "disposable", VIRKI_EMAIL_WORKER_DEDICATED_DB: "confirmed",
    DATABASE_URL: databaseUrl, VIRKI_INTEGRATION_DATABASE_URL: databaseUrl,
    MIGRATION_DATABASE_URL: migrationUrl, AUDIT_LOG_RETENTION_DAYS: "180",
    VIRKI_PORTAL_URL: "http://localhost:3000", VIRKI_HUB_URL: "http://localhost:3001",
    VIRKI_OIDC_ADAPTER_KEY: keys[0], VIRKI_TOTP_ENCRYPTION_KEY: keys[1],
    VIRKI_EMAIL_OUTBOX_KEY: keys[2]
  };
}

export function requireSignedDockerCli(result) {
  if (result?.error || result?.status !== 0 || result.stdout?.trim() !== "VALID_DOCKER_CLI") {
    throw new Error("Local HOL refuses Docker CLI without a valid Docker Inc Authenticode signature.");
  }
}

export function requireHolImage(inspection) {
  const split = typeof inspection === "string" ? inspection.indexOf("|") : -1;
  const id = inspection?.slice(0, split);
  let refs;
  try { refs = JSON.parse(inspection.slice(split + 1)); } catch { /* fail closed */ }
  if (split < 0 || !ID.test(id) || !Array.isArray(refs) ||
      !refs.some((ref) => ref === `postgres@${HOL_IMAGE_DIGEST}` ||
        ref === `docker.io/library/postgres@${HOL_IMAGE_DIGEST}`)) {
    throw new Error("Local HOL PostgreSQL image digest is not independently verified.");
  }
  return id;
}

export function requireHolPlatform(platform) {
  if (platform !== "linux|amd64") throw new Error("Local HOL requires linux/amd64 PG17.");
}

export function requireHolContainerImage(inspection, id) {
  if (!ID.test(id) || inspection !== `${id}|${HOL_IMAGE}`) {
    throw new Error("Local HOL container does not match the pinned PG17 image.");
  }
}

export function requireHolPort(port) {
  const match = /^127\.0\.0\.1:([1-9]\d{0,4})$/u.exec(port);
  if (!match || Number(match[1]) > 65535) throw new Error("Local HOL PostgreSQL port is not single loopback.");
  return match[1];
}

export function requireHolPostgresVersion(version) {
  if (!/^17\d{4}$/u.test(version)) throw new Error("Local HOL PostgreSQL server is not major 17.");
}

export function requireHolOwner({ owner, name, database }) {
  if (!UUID.test(owner) || name !== `virki-email-hol-local-${owner}` || !DB.test(database)) {
    throw new Error("Local HOL owned container/database identities are not unique and scoped.");
  }
}

export function requireHolContainerIdentity(inspection, { owner, name, expectedId }) {
  const parts = typeof inspection === "string" ? inspection.trim().split("|") : [];
  if (parts.length !== 4 || !CID.test(parts[0]) ||
      (expectedId && parts[0] !== expectedId) || parts[1] !== `/${name}` ||
      parts[2] !== owner || parts[3] !== HOL_KIND) {
    throw new Error("Local HOL container lacks exact immutable owner and kind identity.");
  }
  return parts[0];
}

// Every removal is by the verified immutable ID, never mutable name or filters.
// On a lost RUN ACK, lack of a matching name is NOT proof of cleanup.
export function reconcileLocalHolContainer({ invoke, owner, name, containerId, uncertainStart, record }) {
  const inspectFormat = `{{.Id}}|{{.Name}}|{{index .Config.Labels "${HOL_OWNER_LABEL}"}}|{{index .Config.Labels "${HOL_KIND_LABEL}"}}`;
  const inspect = (target) => invoke(["inspect", "--format", inspectFormat, target], 15_000);
  const missing = (result, target) => {
    if (result?.error || result?.status === 0 || typeof result?.stderr !== "string") return false;
    const last = result.stderr.trim().split(/\r?\n/u).at(-1);
    return [`Error: No such object: ${target}`,
      `Error response from daemon: No such object: ${target}`,
      `Error response from daemon: No such container: ${target}`,
      // Docker Desktop 29.x emits this exact lowercase diagnostic after rm.
      `error: no such object: ${target}`].includes(last);
  };
  const target = containerId ?? name;
  const first = inspect(target);
  if (missing(first, target)) {
    if (uncertainStart) throw new Error("Local HOL lost RUN ACK; absent container is not proof of cleanup.");
    record("AUTO_REMOVED_CONFIRMED", containerId);
    return;
  }
  if (first?.error || first?.status !== 0) throw new Error("Local HOL owner inspect was inconclusive.");
  const id = requireHolContainerIdentity(first.stdout, { owner, name, expectedId: containerId });
  const second = inspect(id);
  if (second?.error || second?.status !== 0 ||
      requireHolContainerIdentity(second.stdout, { owner, name, expectedId: id }) !== id) {
    throw new Error("Local HOL container ownership changed before deletion.");
  }
  record("REMOVE_PENDING", id);
  const removed = invoke(["rm", "--force", "--volumes", id], 30_000);
  if (removed?.error || removed?.status !== 0 || !missing(inspect(id), id)) {
    throw new Error("Local HOL owned container removal could not be independently verified.");
  }
  record("CLEANUP_CONFIRMED", id);
}
