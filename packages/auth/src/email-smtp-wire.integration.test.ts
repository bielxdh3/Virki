// EXCLUSIVE: run only through scripts/e2e/run-isolated-linux-docker.ps1
// -IntegrationOnly -IntegrationTestFile packages/auth/src/email-smtp-wire.integration.test.ts.
// The dedicated runner supplies a fresh, isolated PostgreSQL DB and removes
// Docker bootstrap egress before this test starts. Never use real SMTP/mailboxes.
import assert from "node:assert/strict";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";
import { prisma } from "@virki/database";
import { createTestUser, integrationOptions } from "./integration-fixtures";
import { createTotpSecret } from "./security";
import { startMultiMethodRecovery, verifyMultiMethodRecoveryEmail } from "./recovery-methods";
import { createLoopbackSmtpSink } from "../../../scripts/integration/loopback-smtp-sink.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const sender = "wire-sender@integration.invalid";
const account = "smtp-wire@integration.invalid";
const guard = process.env.VIRKI_EMAIL_WIRE_DEDICATED_DB === "confirmed" &&
  process.env.NODE_ENV === "test" &&
  process.env.VIRKI_CORE_TEST_DATABASE_CONFIRM === "disposable" &&
  process.env.VIRKI_INTEGRATION_ENABLED === "true";

after(() => prisma.$disconnect());

function makeCertificates(directory: string) {
  const ca = path.join(directory, "ca.pem");
  const caKey = path.join(directory, "ca.key");
  const leaf = path.join(directory, "leaf.pem");
  const leafKey = path.join(directory, "leaf.key");
  const request = path.join(directory, "leaf.csr");
  const extensions = path.join(directory, "leaf.ext");
  writeFileSync(extensions,
    "basicConstraints=critical,CA:FALSE\nsubjectAltName=IP:127.0.0.1\n" +
    "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n",
    { mode: 0o600 });
  const invoke = (args: string[]) => {
    const result = spawnSync("openssl", args, {
      cwd: directory, stdio: "ignore", timeout: 12_000,
      windowsHide: true, env: { PATH: "/usr/bin:/bin", LANG: "C" }
    });
    if (result.error || result.status !== 0) {
      throw new Error("Disposable OpenSSL certificate generation failed.");
    }
  };
  invoke(["req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "1",
    "-keyout", caKey, "-out", ca, "-subj", "/CN=virki-wire-test-CA",
    "-addext", "basicConstraints=critical,CA:TRUE",
    "-addext", "keyUsage=critical,keyCertSign,cRLSign"]);
  invoke(["req", "-new", "-newkey", "rsa:2048", "-nodes",
    "-keyout", leafKey, "-out", request, "-subj", "/CN=127.0.0.1"]);
  invoke(["x509", "-req", "-sha256", "-days", "1", "-in", request,
    "-CA", ca, "-CAkey", caKey, "-CAcreateserial", "-out", leaf,
    "-extfile", extensions]);
  return {
    ca, certificate: readFileSync(leaf), privateKey: readFileSync(leafKey)
  };
}

async function stopWorker(child: ChildProcess | undefined) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const ended = new Promise<void>((resolve) => child.once("exit", () => resolve()));
  child.kill("SIGTERM");
  let stopTimer: ReturnType<typeof setTimeout> | undefined;
  const stopped = await Promise.race([
    ended.then(() => true),
    new Promise<boolean>((resolve) => { stopTimer = setTimeout(() => resolve(false), 2_500); })
  ]);
  if (stopTimer) clearTimeout(stopTimer);
  if (!stopped) {
    child.kill("SIGKILL");
    let killTimer: ReturnType<typeof setTimeout> | undefined;
    await Promise.race([ended, new Promise((resolve) => {
      killTimer = setTimeout(resolve, 2_500);
    })]);
    if (killTimer) clearTimeout(killTimer);
  }
}

async function waitForSent(recipient: string, isExited: () => boolean) {
  const deadline = Date.now() + 12_000;
  while (Date.now() < deadline) {
    const row = await prisma.emailOutboxMessage.findFirst({
      where: { recipientEmail: recipient, kind: "ACCOUNT_RECOVERY" },
      select: {
        status: true, attemptCount: true, pendingSmtpHeaderMessageId: true,
        deliveryAttempts: { select: { status: true, attempt: true, smtpHeaderMessageId: true } }
      }
    });
    if (row?.status === "SENT") return row;
    if (row?.status === "TERMINAL_FAILURE" || isExited()) break;
    await new Promise((resolve) => setTimeout(resolve, 75));
  }
  throw new Error("Worker did not finalize the local SMTP handoff.");
}

async function assertPlaintextAuthDenied(port: number) {
  await new Promise<void>((resolve, reject) => {
    const socket = connect({ host: "127.0.0.1", port });
    const deadline = setTimeout(() => {
      socket.destroy();
      reject(new Error("Plaintext SMTP denial was not observed."));
    }, 2_000);
    let replied = "";
    let sent = false;
    socket.on("error", () => {
      clearTimeout(deadline);
      reject(new Error("Local SMTP plaintext check failed."));
    });
    socket.on("data", (chunk: Buffer) => {
      replied += chunk.toString("utf8");
      if (!sent && replied.startsWith("220 ")) {
        sent = true;
        socket.write("EHLO local.test\r\nAUTH PLAIN " +
          Buffer.from("\0forbidden@integration.invalid\0wrong").toString("base64") + "\r\n");
      }
      if (replied.includes("530 STARTTLS and EHLO required")) {
        clearTimeout(deadline);
        socket.destroy();
        resolve();
      }
    });
  });
}

test("real worker sends queued recovery OTP over verified loopback STARTTLS AUTH and rejects replay",
  integrationOptions, async () => {
    assert.ok(guard, "The isolated SMTP wire runner must opt in explicitly.");
    const database = new URL(process.env.DATABASE_URL ?? "");
    assert.equal(database.hostname, "127.0.0.1");
    assert.equal(database.username, "virki_runtime_test");
    assert.equal(database.pathname, "/virki_e2e_test");
    assert.equal(database.search, "?schema=public");
    assert.equal(process.env.DATABASE_URL, process.env.VIRKI_INTEGRATION_DATABASE_URL);
    assert.equal(await prisma.emailOutboxMessage.count(), 0, "SMTP wire DB must have a virgin outbox.");
    assert.equal(await prisma.emailDeliveryAttempt.count(), 0);
    assert.equal(await prisma.user.count(), 0, "SMTP wire DB must contain no inherited users.");
    const ipv4Routes = readFileSync("/proc/net/route", "utf8").split(/\r?\n/u).slice(1);
    assert.equal(ipv4Routes.some((route) => /^\S+\s+00000000\s+/u.test(route)), false,
      "The Docker test namespace must have no IPv4 default route.");
    const dirtySmtp = Object.keys(process.env).filter((key) =>
      key.startsWith("VIRKI_EMAIL_SMTP_") || key === "NODE_EXTRA_CA_CERTS" ||
      key === "VIRKI_EMAIL_TRANSPORT");
    assert.deepEqual(dirtySmtp, [], "SMTP wire suite may not inherit a provider endpoint or credential.");
    assert.equal(existsSync("/proc/self/ns/net"), true, "Linux namespace isolation is required.");

    const directory = mkdtempSync(path.join(tmpdir(), "virki-smtp-wire-"));
    let sink: Awaited<ReturnType<typeof createLoopbackSmtpSink>> | undefined;
    let worker: ChildProcess | undefined;
    try {
      const certificates = makeCertificates(directory);
      const transportPassword = randomBytes(32).toString("hex");
      const outboxKey = randomBytes(32).toString("base64url");
      process.env.VIRKI_EMAIL_OUTBOX_KEY = outboxKey;
      const owner = await createTestUser({ label: "smtp-wire-otp", totpSecret: createTotpSecret() });
      const recovery = await startMultiMethodRecovery(owner.email, "USER",
        { proofs: ["TOTP", "EMAIL"], adminReview: false }, "pt-BR");
      assert.equal(await prisma.emailOutboxMessage.count(), 1, "One recovery message must be queued.");
      const queued = await prisma.emailOutboxMessage.findFirstOrThrow({
        where: { recipientEmail: owner.email, kind: "ACCOUNT_RECOVERY" },
        select: { status: true, attemptCount: true }
      });
      assert.equal(queued.status, "QUEUED");
      assert.equal(queued.attemptCount, 0);

      sink = await createLoopbackSmtpSink({
        certificate: certificates.certificate, privateKey: certificates.privateKey,
        username: account, password: transportPassword, recipient: owner.email
      });
      await assertPlaintextAuthDenied(sink.port);
      assert.deepEqual(sink.observations(), { accepted: 0, authenticated: 0, upgraded: 0 },
        "Plaintext AUTH must never receive authorization.");
      // Build the worker environment from an allowlist. Do not forward .env,
      // proxy settings, SMTP credentials, ambient test configuration or logs.
      const env = {
        NODE_ENV: "test",
        DATABASE_URL: process.env.DATABASE_URL!,
        VIRKI_EMAIL_TRANSPORT: "smtp",
        VIRKI_EMAIL_OUTBOX_KEY: outboxKey,
        VIRKI_EMAIL_SMTP_HOST: "127.0.0.1",
        VIRKI_EMAIL_SMTP_PORT: String(sink.port),
        VIRKI_EMAIL_SMTP_SECURE: "false",
        VIRKI_EMAIL_SMTP_USER: account,
        VIRKI_EMAIL_SMTP_PASSWORD: transportPassword,
        VIRKI_EMAIL_FROM: sender,
        NODE_EXTRA_CA_CERTS: certificates.ca,
        VIRKI_EMAIL_MIN_SEND_INTERVAL_MS: "250",
        VIRKI_PORTAL_URL: "http://localhost:3000",
        VIRKI_HUB_URL: "http://localhost:3001",
        VIRKI_OIDC_ADAPTER_KEY: randomBytes(32).toString("hex")
      };
      const tsx = path.join(root, "node_modules/tsx/dist/cli.mjs");
      assert.ok(existsSync(tsx), "A locally installed tsx runtime is required.");
      worker = spawn(process.execPath, [tsx, "packages/auth/src/email-worker.ts"], {
        cwd: root, env, stdio: "ignore", windowsHide: true
      });
      let exited = false;
      worker.once("error", () => { exited = true; });
      worker.once("exit", () => { exited = true; });
      const receipt = await sink.received;
      const sent = await waitForSent(owner.email, () => exited);
      assert.deepEqual(sink.observations(), { accepted: 1, authenticated: 1, upgraded: 1 });
      assert.equal(sent.attemptCount, 1);
      assert.equal(sent.pendingSmtpHeaderMessageId, null);
      assert.equal(sent.deliveryAttempts.length, 1);
      assert.equal(sent.deliveryAttempts[0]?.status, "SENT");
      assert.equal(sent.deliveryAttempts[0]?.attempt, 1);
      assert.equal(sent.deliveryAttempts[0]?.smtpHeaderMessageId, receipt.messageId);
      assert.ok(/^\d{6}$/u.test(receipt.code), "The received body must carry exactly one numeric OTP.");

      const incorrect = receipt.code === "000000" ? "000001" : "000000";
      await assert.rejects(
        verifyMultiMethodRecoveryEmail(recovery.requestId, recovery.requestKey,
          recovery.browserToken, incorrect, "USER"),
        "A wrong code must not complete verification."
      );
      await verifyMultiMethodRecoveryEmail(recovery.requestId, recovery.requestKey,
        recovery.browserToken, receipt.code, "USER");
      const saved = await prisma.accountRecoveryRequest.findUniqueOrThrow({
        where: { id: recovery.requestId }, select: { status: true, emailVerifiedAt: true }
      });
      assert.ok(saved.emailVerifiedAt, "The SMTP-delivered code must prove the owner.");
      assert.equal(saved.status, "PENDING", "The independent TOTP proof remains required.");
      await assert.rejects(
        verifyMultiMethodRecoveryEmail(recovery.requestId, recovery.requestKey,
          recovery.browserToken, receipt.code, "USER"),
        "An accepted OTP must be one-use."
      );
    } finally {
      await stopWorker(worker);
      if (sink) await sink.close();
      delete process.env.VIRKI_EMAIL_OUTBOX_KEY;
      rmSync(directory, { recursive: true, force: true, maxRetries: 2 });
    }
  });
