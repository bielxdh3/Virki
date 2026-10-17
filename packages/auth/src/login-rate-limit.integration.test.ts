import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { PrismaClient, prisma } from "@virki/database";
import { createTestUser, integrationOptions, uniqueEmail } from "./integration-fixtures";
import { authenticateUserWithRateLimit, cleanupExpiredLoginRateLimits, hashPassword, verifyPassword } from "./index";

// Source buckets are shared across runs of this disposable database; start from a clean limiter.
before(async () => {
  if (integrationOptions.skip === false) await prisma.loginRateLimit.deleteMany({});
});
after(() => prisma.$disconnect());

let sourceCounter = 0;
function nextSource(): string {
  sourceCounter += 1;
  return `198.51.100.${(sourceCounter % 250) + 1}`;
}

test("login returns the user for the right password and a generic failure otherwise", integrationOptions, async () => {
  const user = await createTestUser({ label: "login-basic" });
  const source = nextSource();
  const ok = await authenticateUserWithRateLimit(user.email, user.password, new Date(), source);
  assert.equal(ok.user?.id, user.id);
  const wrong = await authenticateUserWithRateLimit(user.email, "not-the-password", new Date(), source);
  assert.deepEqual(wrong, { user: null, failureMode: "invalid-credentials" });
});

test("an unknown email fails generically and still pays for an Argon2 verification", integrationOptions, async () => {
  const sample = await hashPassword("timing-sample");
  await verifyPassword(sample, "warm-up");
  const verifyStarted = performance.now();
  await verifyPassword(sample, "timing-sample-wrong");
  const verifyMs = performance.now() - verifyStarted;

  const started = performance.now();
  const result = await authenticateUserWithRateLimit(uniqueEmail("unknown"), "whatever-password", new Date(), nextSource());
  const elapsed = performance.now() - started;
  assert.deepEqual(result, { user: null, failureMode: "invalid-credentials" });
  assert.ok(elapsed >= verifyMs * 0.5, `unknown-email login took ${elapsed.toFixed(1)}ms, one verification takes ${verifyMs.toFixed(1)}ms`);
});

test("sequential wrong passwords are limited after five attempts", integrationOptions, async () => {
  const user = await createTestUser({ label: "login-sequential" });
  const source = nextSource();
  const results: string[] = [];
  for (let attempt = 0; attempt < 12; attempt += 1) {
    const result = await authenticateUserWithRateLimit(user.email, `wrong-${attempt}`, new Date(), source);
    results.push(result.failureMode ?? "success");
  }
  assert.deepEqual(results.slice(0, 5), Array(5).fill("invalid-credentials"));
  assert.deepEqual(results.slice(5), Array(7).fill("rate-limited"));
  const blockedCorrect = await authenticateUserWithRateLimit(user.email, user.password, new Date(), source);
  assert.equal(blockedCorrect.failureMode, "rate-limited", "the correct password does not bypass an active block");
});

test("a correct password clears the counters", integrationOptions, async () => {
  const user = await createTestUser({ label: "login-clears" });
  const source = nextSource();
  for (let attempt = 0; attempt < 4; attempt += 1) await authenticateUserWithRateLimit(user.email, "wrong", new Date(), source);
  assert.ok((await authenticateUserWithRateLimit(user.email, user.password, new Date(), source)).user);
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const result = await authenticateUserWithRateLimit(user.email, "wrong", new Date(), source);
    assert.equal(result.failureMode, "invalid-credentials");
  }
});

test("50 concurrent wrong guesses from distinct sources never exceed the account limit", integrationOptions, async () => {
  const user = await createTestUser({ label: "login-concurrent" });
  const results = await Promise.all(
    Array.from({ length: 50 }, (_, index) =>
      authenticateUserWithRateLimit(user.email, `wrong-${index}`, new Date(), `198.51.100.${index + 1}`)
    )
  );
  const count = (mode: string) => results.filter((result) => result.failureMode === mode).length;
  assert.equal(count("limiter-unavailable"), 0);
  assert.ok(count("invalid-credentials") <= 20, `${count("invalid-credentials")} guesses were verified`);
  assert.equal(count("invalid-credentials") + count("rate-limited"), 50);
});

test("Argon2 runs outside any database transaction and concurrent logins all succeed", integrationOptions, async () => {
  const monitor = new PrismaClient();
  try {
    const sample = await hashPassword("timing-sample");
    await verifyPassword(sample, "warm-up");
    const verifyStarted = performance.now();
    await verifyPassword(sample, "timing-sample");
    const verifyMs = performance.now() - verifyStarted;
    for (const concurrency of [1, 10, 50]) {
      const users = await Promise.all(Array.from({ length: concurrency }, (_, index) => createTestUser({ label: `login-load-${index}` })));
      let maxTransactionAgeMs = 0;
      let polling = true;
      const poller = (async () => {
        while (polling) {
          const rows = await monitor.$queryRaw<Array<{ age: number | null }>>`
            SELECT max(extract(epoch FROM (clock_timestamp() - xact_start)) * 1000)::float8 AS age
            FROM pg_stat_activity
            WHERE xact_start IS NOT NULL AND pid <> pg_backend_pid() AND datname = current_database()
          `;
          maxTransactionAgeMs = Math.max(maxTransactionAgeMs, rows[0]?.age ?? 0);
          await new Promise((resolve) => setTimeout(resolve, 5));
        }
      })();
      const started = performance.now();
      const results = await Promise.all(
        users.map((user, index) => authenticateUserWithRateLimit(user.email, user.password, new Date(), `198.51.100.${(index % 250) + 1}`))
      );
      const wallMs = performance.now() - started;
      polling = false;
      await poller;
      console.log(`concurrent correct logins: ${concurrency}, wall ${wallMs.toFixed(0)}ms, longest open transaction ${maxTransactionAgeMs.toFixed(0)}ms, one verification ${verifyMs.toFixed(0)}ms`);
      assert.equal(results.filter((result) => result.user).length, concurrency, JSON.stringify(results.filter((result) => !result.user)));
      // Old code held a transaction (and two advisory locks) open for the whole verification; a short
      // reservation or clear transaction stays well below one verification.
      // Asserted only without contention; under concurrency the figure depends on runner load and is reported only.
      if (concurrency === 1) assert.ok(maxTransactionAgeMs < verifyMs, `a transaction stayed open ${maxTransactionAgeMs.toFixed(0)}ms`);
    }
  } finally {
    await monitor.$disconnect();
  }
});


test("owner successes cannot erase interleaved guesses from other sources", integrationOptions, async () => {
  const user = await createTestUser({ label: "login-interleaved" });
  for (let index = 0; index < 20; index += 1) {
    if (index < 19) assert.ok((await authenticateUserWithRateLimit(user.email, user.password, new Date(), "192.0.2.201")).user);
    assert.equal((await authenticateUserWithRateLimit(user.email, "wrong", new Date(), `192.0.2.${index + 1}`)).failureMode, "invalid-credentials");
  }
  assert.equal((await authenticateUserWithRateLimit(user.email, "wrong", new Date(), "192.0.2.202")).failureMode, "rate-limited");
});

test("expired cleanup observes limiter locks and preserves a concurrently refreshed row", integrationOptions, async () => {
  const identifier = `cleanup-lock-${crypto.randomUUID()}`;
  const { createRateLimitIdentifierHash } = await import("./rate-limit-config");
  const hash = createRateLimitIdentifierHash(identifier);
  const now = new Date();
  await prisma.loginRateLimit.create({ data: { identifierHash: hash, attempts: 1, windowStartedAt: new Date(now.getTime() - 86400_000), expiresAt: new Date(now.getTime() - 1000) } });
  let release!: () => void;
  let locked!: () => void;
  const lockReady = new Promise<void>((resolve) => { locked = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const writer = prisma.$transaction(async (transaction) => {
    await transaction.$queryRaw`SELECT pg_advisory_xact_lock(hashtextextended(${hash}, 0)) IS NULL AS "locked"`;
    locked();
    await gate;
    await transaction.loginRateLimit.update({ where: { identifierHash: hash }, data: { expiresAt: new Date(now.getTime() + 86400_000), windowStartedAt: now } });
  });
  await lockReady;
  let cleaned = false;
  const cleanup = cleanupExpiredLoginRateLimits(now).then(() => { cleaned = true; });
  await new Promise((resolve) => setTimeout(resolve, 100));
  try { assert.equal(cleaned, false, "cleanup must honor the writer's advisory lock"); }
  finally { release(); await writer; await cleanup; }
  assert.equal(await prisma.loginRateLimit.count({ where: { identifierHash: hash } }), 1);
});
