import assert from "node:assert/strict";
import { fsyncSync, lstatSync, readFileSync, mkdtempSync, renameSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createDisposableDockerSession } from "./lib/disposable-docker-session.mjs";
import { requireOwnedDisposableDockerMutation, verifyTrustedRoleSetup } from "./lib/disposable-docker-mutation-policy.mjs";
import { assertion as pinnedRuntimeAssertion } from "./lib/production-boundary-assertion.mjs";

const OWNER = "a".repeat(32);

test("real role initializer path is regular and rejects simulated leaf, parent or inode replacement", () => {
  const pinned = verifyTrustedRoleSetup();
  assert.ok(pinned.length > 0);
  for (const suffix of ["10-virki-database-roles.sh", "postgres-init"]) {
    const observe = (pathname, options) => {
      const actual = lstatSync(pathname, options);
      if (path.basename(pathname) !== suffix) return actual;
      return { ...actual, isSymbolicLink: () => true };
    };
    assert.throws(() => verifyTrustedRoleSetup({ observe }), /unsafe path, inode or symlink/u);
  }
  assert.throws(() => verifyTrustedRoleSetup({ previous: `${pinned}tampered` }),
    /initializer inode or parent changed/u);
});

test("reviewed runtime and migrator profiles accept exact owned operations only", () => {
  const runtime = { kind: "runtime", owner: OWNER, containers: ["public-run", "hub-run", "issuer-run"],
    network: "validation-network" };
  const label = `org.virki.validation=${OWNER}`;
  const revision = "a".repeat(40);
  const img = `virki-production-ci:${revision}`;
  const base = ["--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
    "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m"];
  const check = (context, stage, args) => assert.doesNotThrow(() =>
    requireOwnedDisposableDockerMutation({ ...context, stage, args }), stage);
  check(runtime, "create-network", ["network", "create", "--label", label, runtime.network]);
  const publicArgs = ["run", ...base, "--tmpfs",
    "/app/apps/public-site/.next/cache:rw,noexec,nosuid,nodev,size=128m",
    "--detach", "--name", "public-run", "--network", runtime.network, "--label", label,
    "--publish", "127.0.0.1::3000", "--env", "NODE_ENV=production",
    "--env", "VIRKI_PORTAL_URL=https://portal.biel.dev.br", img,
    "npm", "run", "start", "--workspace", "@virki/public-site"];
  check(runtime, "create-public", publicArgs);
  // These mounts are part of the reviewed privilege boundary; accepting an
  // omitted or duplicate tmpfs silently changes runtime security semantics.
  const firstTmpfs = publicArgs.indexOf("--tmpfs");
  for (const flags of [
    [...publicArgs.slice(0, firstTmpfs), ...publicArgs.slice(firstTmpfs + 2)],
    [...publicArgs.slice(0, -6), "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m", ...publicArgs.slice(-6)],
  ]) {
    assert.throws(() => requireOwnedDisposableDockerMutation({ ...runtime,
      stage: "create-public", args: flags }), /refused/u);
  }
  const imageIndex = publicArgs.indexOf(img);
  for (const injection of [
    ["--env", "NODE_OPTIONS=--require=/tmp/rogue.js"],
    ["--env", "DATABASE_URL=postgresql://untrusted-host/other"],
    ["--privileged"],
    ["--host", "tcp://remote.example.invalid:2376"],
  ]) assert.throws(() => requireOwnedDisposableDockerMutation({ ...runtime,
    stage: "create-public", args: [...publicArgs.slice(0, imageIndex), ...injection,
      ...publicArgs.slice(imageIndex)] }), /refused/u);
  check(runtime, "create-issuer", ["run", ...base, "--detach", "--name", "issuer-run",
    "--network", runtime.network, "--label", label, "--network-alias", "oidc-issuer",
    "--env", "NODE_ENV=production", "--env", "OIDC_ISSUER_PORT=3003",
    "--env", "VIRKI_OIDC_ISSUER=https://portal.biel.dev.br",
    "--env", `VIRKI_OIDC_SIGNING_JWKS=${JSON.stringify({ keys: [{ kty: "EC", crv: "P-256", alg: "ES256", use: "sig", d: "secret" }] })}`,
    "--env", `VIRKI_OIDC_COOKIE_KEY=${"A".repeat(43)}`,
    "--env", `VIRKI_OIDC_ADAPTER_KEY=${"a".repeat(64)}`,
    "--env", `VIRKI_TOTP_ENCRYPTION_KEY=${"a".repeat(64)}`,
    "--env", "DATABASE_URL=postgresql://virki_app:local-validation-only@database:5432/virki",
    img, "npm", "run", "start", "--workspace", "@virki/issuer"]);
  check(runtime, "create-hub", ["run", ...base, "--tmpfs",
    "/app/apps/hub/.next/cache:rw,noexec,nosuid,nodev,size=128m", "--detach", "--name", "hub-run",
    "--network", runtime.network, "--label", label, "--publish", "127.0.0.1::3001",
    "--env", "NODE_ENV=production",
    "--env", "VIRKI_HUB_URL=https://hub.biel.dev.br",
    "--env", "VIRKI_PORTAL_URL=https://portal.biel.dev.br",
    "--env", "VIRKI_HUB_HOSTNAME=hub.biel.dev.br",
    "--env", "VIRKI_PORTAL_HOSTNAME=portal.biel.dev.br",
    "--env", "VIRKI_OIDC_PROXY_URL=http://oidc-issuer:3003",
    "--env", "DATABASE_URL=postgresql://virki_app:local-validation-only@database:5432/virki",
    ...["VIRKI_RATE_LIMIT_HASH_SECRET", "VIRKI_AUDIT_HASH_SECRET", "VIRKI_CSRF_SIGNING_KEY",
      "VIRKI_TOTP_ENCRYPTION_KEY", "VIRKI_EMAIL_OUTBOX_KEY", "VIRKI_OIDC_ADAPTER_KEY"]
      .flatMap((key) => ["--env", `${key}=${"a".repeat(64)}`]),
    "--env", "CLOUDFLARE_ACCESS_JWT_REQUIRED=true",
    "--env", "CLOUDFLARE_ACCESS_AUDIENCE=runtime-smoke-audience",
    "--env", "CLOUDFLARE_TEAM_DOMAIN=runtime.example.invalid", img]);
  check(runtime, "run-assertion", ["run", "--rm", "--name", "public-run", "--label", label,
    "--network", "none", ...base, "--entrypoint", "node", img, "-e", pinnedRuntimeAssertion]);
  assert.throws(() => requireOwnedDisposableDockerMutation({ ...runtime, stage: "run-assertion",
    args: ["run", "--rm", "--name", "public-run", "--label", label, "--network", "none",
      ...base, "--entrypoint", "node", img, "-e", "process.exit(0)"] }), /refused/u);

  const id = "b".repeat(8) + "-cccc-dddd-eeee-" + "f".repeat(12);
  const migrator = { kind: "migrator", owner: OWNER,
    containers: ["db-run", "deploy-run", "status-run"], network: "isolated-net" };
  check(migrator, "create-network", ["network", "create", "--internal", "--label", label, migrator.network]);
  const databaseArgs = ["run", "--detach", "--name", "db-run",
    "--network", migrator.network, "--network-alias", `database-${id}`,
    "--label", label, "--env", "POSTGRES_USER", "--env", "POSTGRES_PASSWORD",
    "--env", "POSTGRES_DB", "--env", "VIRKI_RUNTIME_DB_PASSWORD",
    "--env", "VIRKI_MIGRATOR_DB_PASSWORD", "--env", "VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD",
    "--volume", `${path.resolve("infra/postgres-init/10-virki-database-roles.sh")}:/docker-entrypoint-initdb.d/10-virki-database-roles.sh:ro`,
    "postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24"];
  check(migrator, "create-database", databaseArgs);
  assert.throws(() => requireOwnedDisposableDockerMutation({ ...migrator,
    stage: "create-database", args: databaseArgs.map((v) => v.includes("postgres-init/") ||
      v.includes("postgres-init\\") ? v.replace(/^[^:]+/u, "C:/foreign/infra/postgres-init/10-virki-database-roles.sh") : v),
  }), /refused/u);
  for (const [stage, name, command] of [
    ["run-deploy", "deploy-run", "prisma:migrate:deploy"],
    ["run-status", "status-run", "prisma:migrate:status"],
  ]) check(migrator, stage, ["run", ...base, "--rm", "--name", name,
    "--network", migrator.network, "--label", label, "--env", "MIGRATION_DATABASE_URL",
    `virki-migrator-ci:${revision}`, "npm", "run", command]);
});

function receipt(pathname) {
  return JSON.parse(readFileSync(pathname, "utf8").trim().split(/\r?\n/u).at(-1));
}

function fixture({ failCreate = false, failStart = false, missingAfterFailure = false, failCleanup = false,
  platform = "win32", nativeArch = "x64", serverArch = "amd64", envOverride = {},
  containers = ["validation-container"] } = {}) {
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-docker-session-test-"));
  const calls = [];
  let exists = false;
  const spawn = (cli, args, options) => {
    calls.push({ cli, args, env: options.env });
    const action = args.slice(2);
    if (action[0] === "version") return { status: 0, stdout: `linux|${serverArch}\n`, stderr: "" };
    if (action[0] === "port") return { status: 0, stdout: "127.0.0.1:30000\n", stderr: "" };
    if (action[0] === "network" && action[1] === "create") {
      exists = !missingAfterFailure;
      return { status: failCreate ? 1 : 0, stdout: "", stderr: failCreate ? "ambiguous Docker CLI timeout" : "" };
    }
    if (action[0] === "run" && failStart) {
      return { status: 1, stdout: "", stderr: "Docker CLI timed out before returning CID" };
    }
    if (action[0] === "run") return { status: 0, stdout: "", stderr: "" };
    if (action[0] === "network" && action[1] === "inspect") {
      if (exists && action[2] === "validation-network") {
        return { status: 0, stdout: JSON.stringify([{ Id: "b".repeat(64), Name: "validation-network", Labels: { "org.virki.validation": OWNER } }]), stderr: "" };
      }
      return { status: 1, stdout: "[]", stderr: `Error response from daemon: network ${action[2]} not found` };
    }
    if (action[0] === "container" && action[1] === "inspect") {
      return { status: 1, stdout: "[]", stderr: `Error response from daemon: No such container: ${action[2]}` };
    }
    if (action[0] === "network" && action[1] === "rm") {
      if (failCleanup) return { status: 1, stdout: "", stderr: "ambiguous removal" };
      exists = false;
      return { status: 0, stdout: "", stderr: "" };
    }
    throw Error(`Unexpected fake Docker action ${action.join(" ")}`);
  };
  const env = { ...process.env, DOCKER_HOST: "tcp://production.example.invalid:2376",
    DOCKER_CONTEXT: "production", DOCKER_TLS_VERIFY: "1",
    VIRKI_VALIDATION_EVIDENCE_DIR: path.join(root, "unused-user-environment-override"), ...envOverride };
  const session = createDisposableDockerSession({ kind: "runtime", owner: OWNER,
    containers, network: "validation-network", env,
    platform, nativeArch, receiptDirectory: root, spawn });
  return { root, calls, session, env, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

test("subprocess environment overrides cannot reroute Docker or disposable databases", (t) => {
  const f = fixture(); t.after(f.cleanup);
  const initialCalls = f.calls.length;
  const ownedNetwork = ["network", "create", "--label", `org.virki.validation=${OWNER}`, "validation-network"];
  for (const dangerous of [
    { ...f.env, LD_PRELOAD: "/tmp/evil.so" },
    { ...f.env, NODE_OPTIONS: "--require=/tmp/rogue.js" },
    { ...f.env, PATH: "/tmp/rogue-bin" },
    { ...f.env, MIGRATION_DATABASE_URL: "postgresql://virki_migrator@foreign.example.test/virki_validation" },
  ]) {
    assert.throws(() => f.session.mutate("create-network", ownedNetwork, { env: dangerous }), /refused/u);
    assert.throws(() => f.session.invoke(["port", "validation-container", "3000/tcp"],
      { env: dangerous }), /refused/u);
  }
  assert.equal(f.calls.length, initialCalls, "unsafe environment must not reach Docker");
  f.session.cleanup(); f.session.finish(true);
});

test("RED→GREEN: reserved Docker networks and resource creation replay are rejected", (t) => {
  for (const network of ["host", "bridge", "none", "default"]) {
    let contacted = false;
    assert.throws(() => createDisposableDockerSession({
      kind: "runtime", owner: OWNER, containers: ["validation-container"], network,
      platform: "win32", spawn: () => { contacted = true; throw Error("Unexpected Docker contact"); },
    }), /invalid resource ownership/u);
    assert.equal(contacted, false);
    assert.throws(() => requireOwnedDisposableDockerMutation({ kind: "runtime", owner: OWNER,
      containers: ["validation-container"], network, stage: "create-network",
      args: ["network", "create", "--label", `org.virki.validation=${OWNER}`, network],
    }), /refused/u);
  }
  const f = fixture(); t.after(f.cleanup);
  const expected = ["network", "create", "--label", `org.virki.validation=${OWNER}`, "validation-network"];
  f.session.mutate("create-network", expected);
  const calls = f.calls.length;
  assert.throws(() => f.session.mutate("create-network", expected), /out-of-order|repeated/u);
  assert.equal(f.calls.length, calls, "replayed network creation must not reach Docker");
  f.session.cleanup(); f.session.finish(true);
});

test("RED→GREEN: runtime containers cannot start before their disposable network", (t) => {
  const f = fixture({ containers: ["public-run", "hub-run", "issuer-run"] });
  t.after(f.cleanup);
  const calls = f.calls.length;
  assert.throws(() => f.session.mutate("create-hub", []), /out-of-order/u);
  assert.equal(f.calls.length, calls);
  f.session.cleanup(); f.session.finish(true);
});

test("explicit Windows Docker Desktop Linux pipe is used, never ambient remote DOCKER_HOST", (t) => {
  const f = fixture(); t.after(f.cleanup);
  f.session.mutate("create-network", ["network", "create", "--label", `org.virki.validation=${OWNER}`, "validation-network"]);
  f.session.cleanup();
  f.session.finish(true);
  assert.ok(f.calls.every(({ cli, args, env }) =>
    cli === "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe" &&
    args[0] === "--host" && args[1] === "npipe:////./pipe/dockerDesktopLinuxEngine" &&
    !Object.keys(env).some((key) => key.startsWith("DOCKER_"))));
});

test("lost Docker create ACK remains unresolved even if immediate inspection says absent", (t) => {
  const f = fixture({ failCreate: true, missingAfterFailure: true }); t.after(f.cleanup);
  assert.throws(() => f.session.mutate("create-network", ["network", "create", "--label", `org.virki.validation=${OWNER}`, "validation-network"]), /uncertain/u);
  f.session.cleanup();
  assert.throws(() => f.session.finish(false), /reconciliation/u);
  const record = receipt(f.session.receiptPath);
  assert.equal(record.status, "RECONCILIATION_REQUIRED");
  assert.equal(record.owner, OWNER);
  assert.deepEqual(record.resources, { containers: ["validation-container"], network: "validation-network" });
  assert.deepEqual(record.uncertainOperations, ["create-network"]);
});

test("ambiguous Docker rm keeps ownership receipt for manual reconciliation", (t) => {
  const f = fixture({ failCleanup: true }); t.after(f.cleanup);
  f.session.mutate("create-network", ["network", "create", "--label", `org.virki.validation=${OWNER}`, "validation-network"]);
  assert.throws(() => f.session.cleanup(), /uncertain/u);
  assert.throws(() => f.session.finish(true), /reconciliation/u);
  const record = receipt(f.session.receiptPath);
  assert.deepEqual(record.uncertainOperations, ["remove-network"]);
  assert.equal(record.status, "RECONCILIATION_REQUIRED");
});

test("a Docker mutation after verified cleanup cannot reuse stale cleanup evidence", (t) => {
  const f = fixture(); t.after(f.cleanup);
  f.session.cleanup();
  const priorCalls = f.calls.length;
  assert.throws(() => f.session.mutate("create-network", ["network", "create",
    "--label", `org.virki.validation=${OWNER}`, "validation-network"]), /after cleanup/u);
  assert.equal(f.calls.length, priorCalls, "post-cleanup creation must not reach Docker");
  f.session.finish(true);
  assert.equal(receipt(f.session.receiptPath).status, "PASS");
});

test("RED→GREEN: one acknowledged image assertion can never replay before cleanup", (t) => {
  const f = fixture(); t.after(f.cleanup);
  const args = ["run", "--rm", "--name", "validation-container",
    "--label", `org.virki.validation=${OWNER}`, "--network", "none",
    "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
    "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m", "--entrypoint", "node",
    `virki-production-ci:${"a".repeat(40)}`, "-e", pinnedRuntimeAssertion];
  assert.equal(f.session.mutate("run-assertion", args).status, 0);
  const originalRuns = f.calls.filter((call) => call.args[2] === "run").length;
  assert.equal(originalRuns, 1);
  assert.throws(() => f.session.mutate("run-assertion", args), /repeated|out-of-order/u);
  assert.equal(f.calls.filter((call) => call.args[2] === "run").length, 1,
    "a replayed assertion must not contact the Docker daemon");
  f.session.cleanup(); f.session.finish(true);
});

test("public Docker reads never expose raw mutation or foreign resource access", (t) => {
  const f = fixture(); t.after(f.cleanup);
  const before = f.calls.length;
  for (const dangerous of [
    ["network", "create", "--label", `org.virki.validation=${OWNER}`, "validation-network"],
    ["container", "rm", "--force", "foreign-container"],
    ["exec", "foreign-container", "sh", "-c", "touch /tmp/foreign"],
    ["port", "foreign-container", "3000/tcp"],
  ]) assert.throws(() => f.session.invoke(dangerous), /refused/u);
  assert.equal(f.calls.length, before, "unreviewed Docker calls cannot reach CLI");
  assert.equal(f.session.invoke(["port", "validation-container", "3000/tcp"]).status, 0);
  f.session.cleanup();
  const afterCleanup = f.calls.length;
  assert.throws(() => f.session.invoke(["network", "create", "validation-network"]), /refused/u);
  assert.equal(f.calls.length, afterCleanup);
  f.session.finish(true);
  assert.equal(receipt(f.session.receiptPath).status, "PASS");
});

test("public Docker mutations cannot target foreign resources or enable host privileges", (t) => {
  const f = fixture(); t.after(f.cleanup);
  const earlierCalls = f.calls.length;
  for (const bad of [
    ["container", "rm", "--force", "foreign-container"],
    ["network", "rm", "foreign-network"],
    ["network", "create", "--label", "org.virki.validation=foreign", "validation-network"],
    ["run", "--privileged", "--name", "validation-container", "--label",
      `org.virki.validation=${OWNER}`, "scratch-local-image"],
    ["run", "--name", "foreign-container", "--label", `org.virki.validation=${OWNER}`,
      "scratch-local-image"],
  ]) assert.throws(() => f.session.mutate("create-network", bad), /refused/u);
  assert.equal(f.calls.length, earlierCalls, "invalid Docker mutations must not contact daemon");
  f.session.cleanup(); f.session.finish(true);
});

test("lost container CID after Docker start cannot be cleared by an absent immediate inspect", (t) => {
  const f = fixture({ failStart: true, missingAfterFailure: true }); t.after(f.cleanup);
  assert.throws(() => f.session.mutate("run-assertion", ["run", "--rm", "--name", "validation-container",
    "--label", `org.virki.validation=${OWNER}`, "--network", "none", "--read-only", "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges:true", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
    "--entrypoint", "node", `virki-production-ci:${"a".repeat(40)}`, "-e", pinnedRuntimeAssertion]), /uncertain/u);
  f.session.cleanup();
  assert.throws(() => f.session.finish(false), /reconciliation/u);
  const record = receipt(f.session.receiptPath);
  assert.deepEqual(record.uncertainOperations, ["run-assertion"]);
  assert.equal(record.resources.containers[0], "validation-container");
  assert.equal(f.calls.some((call) => call.args.includes("--force")), false);
});

test("Linux local/WSL refuses ambient Docker, only claimed trusted hosted CI is allowed", (t) => {
  assert.throws(() => createDisposableDockerSession({ kind: "runtime", owner: OWNER,
    network: "validation-network", containers: [], platform: "linux", env: {},
    spawn: () => { throw Error("Docker must not be contacted"); } }), /trusted runner/u);
  const f = fixture(); t.after(f.cleanup);
  assert.ok(f.session.receiptPath.startsWith(f.root));
  f.session.cleanup(); f.session.finish(true);
});

test("ARM64 hosted Linux matrix is accepted only with matching native process and engine arch", (t) => {
  const linuxEnv = { GITHUB_ACTIONS: "true", CI: "true", RUNNER_OS: "Linux",
    RUNNER_ENVIRONMENT: "github-hosted", RUNNER_ARCH: "ARM64", VIRKI_BUILD_ARCH: "arm64",
    VIRKI_BUILD_REVISION: "b".repeat(40) };
  const f = fixture({ platform: "linux", nativeArch: "arm64", serverArch: "arm64", envOverride: linuxEnv });
  t.after(f.cleanup);
  f.session.mutate("create-network", ["network", "create", "--label", `org.virki.validation=${OWNER}`, "validation-network"]);
  f.session.cleanup(); f.session.finish(true);
  assert.ok(f.calls.every(({ cli }) => cli === "/usr/bin/docker"));
  assert.equal(receipt(f.session.receiptPath).status, "PASS");
});

test("CI matrix architecture spoofing, wrong runner/native arch and Docker daemon mismatch reject", (t) => {
  const good = { GITHUB_ACTIONS: "true", CI: "true", RUNNER_OS: "Linux",
    RUNNER_ENVIRONMENT: "github-hosted", RUNNER_ARCH: "ARM64", VIRKI_BUILD_ARCH: "arm64",
    VIRKI_BUILD_REVISION: "c".repeat(40) };
  for (const variation of [
    { nativeArch: "x64", serverArch: "arm64" },
    { nativeArch: "arm64", serverArch: "amd64" },
    { nativeArch: "arm64", serverArch: "arm64", envOverride: { ...good, RUNNER_ARCH: "X64" } },
    { nativeArch: "arm64", serverArch: "arm64", envOverride: { ...good, VIRKI_BUILD_REVISION: "invalid" } },
  ]) {
    const root = mkdtempSync(path.join(os.tmpdir(), "virki-docker-bad-arch-"));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    assert.throws(() => createDisposableDockerSession({ kind: "runtime", owner: OWNER,
      network: "validation-network", containers: [], platform: "linux",
      nativeArch: variation.nativeArch, receiptDirectory: root,
      env: variation.envOverride ?? good,
      spawn: (_cli, _args) => ({ status: 0, stdout: `linux|${variation.serverArch}\n`, stderr: "" }),
    }), /refused/u);
  }
});

test("receipt root alias and preexisting receipt are rejected before any Docker mutation", (t) => {
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-docker-root-"));
  const fake = mkdtempSync(path.join(os.tmpdir(), "virki-docker-alias-"));
  t.after(() => { rmSync(root, { recursive: true, force: true }); rmSync(fake, { recursive: true, force: true }); });
  const alias = path.join(root, "alias");
  try { symlinkSync(fake, alias, process.platform === "win32" ? "junction" : "dir"); }
  catch (error) {
    if (["EPERM", "EACCES"].includes(error.code)) { t.skip("symlink not permitted by this host"); return; }
    throw error;
  }
  const request = { kind: "runtime", owner: OWNER, network: "validation-network", containers: [],
    receiptDirectory: alias, platform: "win32", spawn: () => { throw Error("Docker may not be contacted"); } };
  assert.throws(() => createDisposableDockerSession(request), /unsafe path alias/u);
  writeFileSync(path.join(root, `runtime-${OWNER}.jsonl`), "preserve-original\n");
  assert.throws(() => createDisposableDockerSession({ ...request, receiptDirectory: root,
    spawn: (_cli, _args) => ({ status: 0, stdout: "linux|amd64\n", stderr: "" }) }), /EEXIST/u);
  assert.equal(readFileSync(path.join(root, `runtime-${OWNER}.jsonl`), "utf8"), "preserve-original\n");
});

test("live path swap after receipt open cannot redirect the pinned journal", (t) => {
  if (process.platform !== "linux") { t.skip("Linux inode swap fixture"); return; }
  const f = fixture();
  t.after(f.cleanup);
  const previous = `${f.session.receiptPath}.previous`;
  const unrelated = path.join(f.root, "unrelated.txt");
  writeFileSync(unrelated, "external-bytes\n");
  renameSync(f.session.receiptPath, previous);
  symlinkSync(unrelated, f.session.receiptPath);
  const previousCalls = f.calls.length;
  assert.throws(() => f.session.mutate("create-network", ["network", "create", "--label",
    `org.virki.validation=${OWNER}`, "validation-network"]),
    /receipt directory or pinned file identity changed/u);
  assert.equal(f.calls.length, previousCalls);
  assert.equal(readFileSync(unrelated, "utf8"), "external-bytes\n");
  unlinkSync(f.session.receiptPath);
  renameSync(previous, f.session.receiptPath);
  f.session.cleanup();
  f.session.finish(false);
  assert.equal(receipt(f.session.receiptPath).status, "SMOKE_FAILED_CLEANED");
});

test("renamed and symlinked parent directory refuses mutation on the original receipt FD", (t) => {
  if (process.platform !== "linux") { t.skip("Linux directory rename fixture"); return; }
  const f = fixture();
  const original = `${f.root}.original`;
  const foreign = mkdtempSync(path.join(os.tmpdir(), "virki-foreign-root-"));
  t.after(() => { rmSync(f.root, { recursive: true, force: true }); rmSync(original, { recursive: true, force: true });
    rmSync(foreign, { recursive: true, force: true }); });
  renameSync(f.root, original);
  symlinkSync(foreign, f.root);
  assert.throws(() => f.session.mutate("create-network", ["network", "create", "--label",
    `org.virki.validation=${OWNER}`, "validation-network"]),
    /unsafe path alias/u);
  unlinkSync(f.root);
  renameSync(original, f.root);
  f.session.cleanup(); f.session.finish(false);
  assert.equal(receipt(f.session.receiptPath).status, "SMOKE_FAILED_CLEANED");
});

test("POSIX fsync failure for receipt directory or parent blocks Docker before first contact", (t) => {
  if (process.platform !== "linux") { t.skip("Linux directory fsync test"); return; }
  const env = {
    GITHUB_ACTIONS: "true", CI: "true", RUNNER_OS: "Linux", RUNNER_ENVIRONMENT: "github-hosted",
    RUNNER_ARCH: "X64", VIRKI_BUILD_ARCH: "amd64", VIRKI_BUILD_REVISION: "a".repeat(40),
  };
  for (const failingDirectory of ["root", "parent"]) {
    const root = mkdtempSync(path.join(os.tmpdir(), "virki-powerloss-sync-"));
    t.after(() => rmSync(root, { force: true, recursive: true }));
    let dockerCalls = 0;
    const syncCalls = [];
    assert.throws(() => createDisposableDockerSession({
      kind: "runtime", owner: OWNER, containers: [], network: "validation-network",
      platform: "linux", nativeArch: "x64", env, receiptDirectory: root,
      spawn: () => { dockerCalls++; return { status: 0, stdout: "linux|amd64\n", stderr: "" }; },
      fsyncDirectory: (fd, label) => {
        syncCalls.push(label);
        if (label === failingDirectory) throw new Error(`injected ${label} fsync EIO`);
        fsyncSync(fd);
      },
    }), /injected (root|parent) fsync EIO/u);
    assert.equal(dockerCalls, 0, "neither preflight nor a Docker mutation should run without durable receipt namespace");
    assert.ok(syncCalls.includes(failingDirectory), `missing ${failingDirectory} fsync barrier`);
  }
});

test("RED→GREEN: unrelated shared /tmp subdirectory changes do not invalidate durable receipt parent", (t) => {
  if (process.platform !== "linux") { t.skip("Linux shared temp parent inode test"); return; }
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-parent-nlink-"));
  let unrelated = null;
  t.after(() => {
    rmSync(root, { recursive: true, force: true });
    if (unrelated) rmSync(unrelated, { recursive: true, force: true });
  });
  let probes = 0;
  const session = createDisposableDockerSession({
    kind: "runtime", owner: OWNER, containers: [], network: "validation-network",
    platform: "linux", nativeArch: "x64", receiptDirectory: root,
    env: { GITHUB_ACTIONS: "true", CI: "true", RUNNER_OS: "Linux",
      RUNNER_ENVIRONMENT: "github-hosted", RUNNER_ARCH: "X64",
      VIRKI_BUILD_ARCH: "amd64", VIRKI_BUILD_REVISION: "a".repeat(40) },
    fsyncDirectory: (fd, label) => {
      fsyncSync(fd);
      if (label === "root") unrelated = mkdtempSync(path.join(os.tmpdir(), "virki-unrelated-nlink-"));
    },
    spawn: (_cli, args) => {
      if (args[2] === "version") { probes++; return { status: 0, stdout: "linux|amd64\n", stderr: "" }; }
      return { status: 1, stdout: "", stderr: `Error response from daemon: network ${args[4]} not found` };
    },
  });
  assert.equal(probes, 1, "unrelated tmp changes must not prevent the pinned local Docker probe");
  session.cleanup(); session.finish(true);
});

test("POSIX persists receipt-root and mkdtemp-parent entries before the first Docker probe", (t) => {
  if (process.platform !== "linux") { t.skip("Linux fsync ordering test"); return; }
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-powerloss-order-"));
  t.after(() => rmSync(root, { force: true, recursive: true }));
  const events = [];
  const session = createDisposableDockerSession({
    kind: "runtime", owner: OWNER, containers: [], network: "validation-network",
    platform: "linux", nativeArch: "x64", receiptDirectory: root,
    env: { GITHUB_ACTIONS: "true", CI: "true", RUNNER_OS: "Linux",
      RUNNER_ENVIRONMENT: "github-hosted", RUNNER_ARCH: "X64", VIRKI_BUILD_ARCH: "amd64",
      VIRKI_BUILD_REVISION: "b".repeat(40) },
    fsyncDirectory: (fd, label) => { fsyncSync(fd); events.push(`fsync:${label}`); },
    spawn: (_cli, args) => {
      if (args[2] === "version") {
        events.push("docker:probe");
        return { status: 0, stdout: "linux|amd64\n", stderr: "" };
      }
      return { status: 1, stdout: "", stderr: `Error response from daemon: network ${args[4]} not found` };
    },
  });
  assert.deepEqual(events, ["fsync:root", "fsync:parent", "docker:probe"]);
  session.cleanup(); session.finish(true);
  assert.equal(receipt(session.receiptPath).status, "PASS");
});
