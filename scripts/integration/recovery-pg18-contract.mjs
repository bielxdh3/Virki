// Exact physical PG18 recovery evidence. A successful process exit is NOT a
// passing integration suite when node:test has silently skipped its tests.
// Independently checked against Docker Hub tag metadata, registry manifest
// Docker-Content-Digest and docker-library/repo-info for 18.6-alpine3.24
// on 2026-11-10. linux/amd64 platform manifest: sha256:300ebd02c6d4de9ee27ad7f6855d5d21b4d3a4a5117767c1197d284c635d9736.
// https://github.com/docker-library/repo-info/blob/master/repos/postgres/remote/18.6-alpine3.24.md
export const RECOVERY_PG18_IMAGE_DIGEST = "sha256:123b17998ccaf47e53b502e8c6a1e79afd8f579c6f3eec83c563da026f957395";
export const RECOVERY_PG18_IMAGE = `postgres:18.6-alpine3.24@${RECOVERY_PG18_IMAGE_DIGEST}`;

const SYSTEM_ENV_KEYS = Object.freeze([
  "PATH", "Path", "SystemRoot", "WINDIR", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
  "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL"
]);
const ADMISSION_ENV_KEYS = Object.freeze([
  "GITHUB_ACTIONS", "CI", "RUNNER_OS", "RUNNER_ENVIRONMENT", "RUNNER_ARCH",
  "VIRKI_BUILD_REVISION", "VIRKI_BUILD_ARCH"
]);

function pickSystemEnvironment(source) {
  return Object.fromEntries(SYSTEM_ENV_KEYS.filter((key) =>
    typeof source[key] === "string" && source[key].length > 0).map((key) => [key, source[key]]));
}

export function privateRecoveryDockerAdmissionEnvironment(source = process.env) {
  return {
    ...pickSystemEnvironment(source),
    ...Object.fromEntries(ADMISSION_ENV_KEYS.filter((key) =>
      typeof source[key] === "string" && source[key].length > 0).map((key) => [key, source[key]]))
  };
}

export function privateRecoveryTestEnvironment({ source = process.env, databaseUrl, migrationUrl, secret }) {
  if (typeof databaseUrl !== "string" || typeof migrationUrl !== "string" ||
      typeof secret !== "function") throw new Error("Private PG18 test env inputs are missing.");
  // Never spread process.env or the Docker client's inherited subprocessEnv.
  // In particular NODE_OPTIONS, NODE_PATH, SMTP, GITHUB_TOKEN and production
  // secrets must never cross into the migration or integration test children.
  return {
    ...pickSystemEnvironment(source),
    NODE_ENV: "test", CI: "true",
    VIRKI_INTEGRATION_ENABLED: "true", VIRKI_CORE_TEST_DATABASE_CONFIRM: "disposable",
    DATABASE_URL: databaseUrl, VIRKI_INTEGRATION_DATABASE_URL: databaseUrl,
    MIGRATION_DATABASE_URL: migrationUrl,
    VIRKI_PORTAL_URL: "http://localhost:3000", VIRKI_HUB_URL: "http://localhost:3001",
    VIRKI_OIDC_ADAPTER_KEY: secret(),
    VIRKI_TOTP_ENCRYPTION_KEY: secret(),
    VIRKI_EMAIL_OUTBOX_KEY: secret()
  };
}

const LOCAL_IMAGE_ID = /^sha256:[a-f0-9]{64}$/u;
const ACCEPTED_REPO_DIGESTS = new Set([
  `postgres@${RECOVERY_PG18_IMAGE_DIGEST}`,
  `docker.io/library/postgres@${RECOVERY_PG18_IMAGE_DIGEST}`
]);

export function verifiedRecoveryPg18LocalImage(inspection) {
  if (typeof inspection !== "string") throw new Error("Private PG18 image inspection missing.");
  const split = inspection.indexOf("|");
  const localId = inspection.slice(0, split);
  if (split === -1 || !LOCAL_IMAGE_ID.test(localId)) {
    throw new Error("Private PG18 image ID missing or invalid.");
  }
  let digests;
  try { digests = JSON.parse(inspection.slice(split + 1)); } catch {
    throw new Error("Private PG18 RepoDigests could not be parsed.");
  }
  if (!Array.isArray(digests) || !digests.some((ref) => ACCEPTED_REPO_DIGESTS.has(ref))) {
    throw new Error("Private PG18 image lacks the exact pinned registry digest.");
  }
  return localId;
}

export function requireRecoveryPg18ImagePlatform(inspection) {
  if (inspection !== "linux|amd64") {
    throw new Error("Private PG18 image is not the admitted linux/amd64 platform.");
  }
}

export function requireRecoveryPg18ContainerImage(inspection, expectedImageId) {
  if (!LOCAL_IMAGE_ID.test(expectedImageId) ||
      inspection !== `${expectedImageId}|${RECOVERY_PG18_IMAGE}`) {
    throw new Error("Private PG18 container image differs from the independently verified digest-pinned image.");
  }
}

export const RECOVERY_PG18_SUITES = Object.freeze([
  Object.freeze({
    kind: "admin-pairs",
    databasePrefix: "virki_w11_admin_pairs_",
    file: "packages/auth/src/recovery-admin-pairs.integration.test.ts",
    names: Object.freeze([
      "PG18 ADMIN normal-password: independent TOTP_EMAIL, cross-role proof and concurrent one-winner",
      "PG18 ADMIN normal-password: signed Hub PASSKEY_EMAIL, RP isolation, flag and replay",
      "PG18 ADMIN normal-password: revoking signed Hub passkey after both proofs invalidates approved reset",
      "PG18 ADMIN normal-password: TOTP key rotation after approval invalidates stale verified step",
      "PG18 ADMIN normal-password: Hub PASSKEY_TOTP requires independently verified new mailbox before reset"
    ])
  }),
  Object.freeze({
    kind: "assisted",
    databasePrefix: "virki_w2_assisted_",
    file: "packages/auth/src/recovery-assisted.integration.test.ts",
    names: Object.freeze([
      "PG18 EMAIL_ADMIN: verified old inbox plus elevated other ADMIN resets USER without replacement mailbox",
      "PG18 TOTP_ADMIN: revoked reviewer cannot consume even after verified replacement inbox",
      "PG18 TOTP_ADMIN: USER reset succeeds only after independent review and new mailbox ownership proof",
      "PG18 PASSKEY_ADMIN: signed hub RP assertion, no self-review, independent elevated ADMIN and pre-reset mailbox safety"
    ])
  })
]);

export function requireExactRecoveryPg18Tap(output, suite) {
  if (typeof output !== "string" || !RECOVERY_PG18_SUITES.includes(suite)) {
    throw new Error("Unrecognized PG18 recovery evidence target.");
  }
  const totals = new Map();
  const names = [];
  const testIds = [];
  for (const line of output.split(/\r?\n/u)) {
    const count = /^# (tests|pass|fail|cancelled|skipped|todo) (\d+)$/u.exec(line);
    if (count) {
      if (totals.has(count[1])) throw new Error("Duplicate PG18 recovery TAP summary.");
      totals.set(count[1], Number(count[2]));
    }
    const passed = /^ok ([1-9]\d*) - (.+)$/u.exec(line);
    if (passed) { testIds.push(Number(passed[1])); names.push(passed[2]); }
    if (/^not ok \d+ - /u.test(line)) throw new Error("A PG18 recovery test failed.");
  }
  const expected = suite.names.length;
  if (totals.size !== 6 || totals.get("tests") !== expected || totals.get("pass") !== expected ||
      totals.get("fail") !== 0 || totals.get("cancelled") !== 0 ||
      totals.get("skipped") !== 0 || totals.get("todo") !== 0 ||
      names.length !== expected ||
      testIds.some((id, index) => id !== index + 1) ||
      names.some((name) => /\s+#\s+(?:SKIP|TODO)\b/iu.test(name)) ||
      JSON.stringify([...names].sort()) !== JSON.stringify([...suite.names].sort())) {
    throw new Error(`PG18 recovery ${suite.kind} must execute exactly ${expected} named PASS, zero SKIP/FAIL/TODO.`);
  }
  return expected;
}
