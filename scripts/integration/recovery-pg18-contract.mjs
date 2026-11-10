// Exact physical PG18 recovery evidence. A successful process exit is NOT a
// passing integration suite when node:test has silently skipped its tests.
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
