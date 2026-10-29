import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync,
  statfsSync, symlinkSync, writeFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { parsePinnedOpenSshEd25519PublicKey } from "../../scripts/lib/offline-ssh-transfer-permit.mjs";
import { inspectOwnerPinnedSshHostKey, renderOwnerPinnedOfflineSshBootstrap,
  verifyRestrictedOfflineSshdEffectiveConfiguration, verifyUnrelatedSshdEffectiveBaselines,
  SHARED_SSHD_BASELINE_CONTEXTS } from "./owner-ssh-bootstrap.mjs";

// REAL OpenSSH sshd + sudoers + client E2E, but ONLY inside an independently
// isolated, disposable /etc+/run+/usr/local/lib tmpfs mount namespace. The
// owner production receiver is deliberately NOT executed; instead a test-only
// receiver at the same fixed absolute pathname records the exact four sudo
// selectors and demonstrates shell/forwarding denial.
const FIXTURE = process.platform === "linux" && process.getuid?.() === 0 &&
  process.env.VIRKI_SSH_DISPOSABLE_E2E === "1" &&
  process.env.VIRKI_SSH_ISOLATED_NETWORK === "1" &&
  statfsSync("/etc").type === 0x01021994 &&
  statfsSync("/run").type === 0x01021994 &&
  statfsSync("/usr/local/lib/virki").type === 0x01021994;
const onlyFixture = { skip: FIXTURE ? false : "Isolated root tmpfs OpenSSH fixture required" };
const SSHD = "/usr/sbin/sshd";
const FILE = "/usr/local/lib/virki/offline-transfer/offline-host-transfer-receiver.mjs";
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
function run(binary, args, options = {}) {
  return spawnSync(binary, args, { encoding: "utf8", timeout: 8000,
    maxBuffer: 8192, ...options });
}
function save(name, bytes, mode = 0o600) {
  writeFileSync(name, bytes, { mode });
  chmodSync(name, mode);
}
function createKey(file) {
  const output = run("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519",
    "-N", "", "-f", file]);
  assert.equal(output.status, 0, output.stderr);
  return readFileSync(file + ".pub", "utf8").trim();
}

test("REAL OpenSSH early Include preserves trailing globals for unrelated users and contexts",
  onlyFixture, (t) => {
    const folder = mkdtempSync("/tmp/virki-sshd-w55-early-include-");
    t.after(() => rmSync(folder, { recursive: true, force: true }));
    mkdirSync("/run/sshd", { recursive: true, mode: 0o755 });
    mkdirSync("/etc/ssh/sshd_config.d", { recursive: true, mode: 0o755 });
    save("/etc/passwd", "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/tmp:/bin/sh\nsshd:x:102:65534:sshd:/run/sshd:/usr/sbin/nologin\n_sshd:x:103:65534:sshd:/run/sshd:/usr/sbin/nologin\n",
      0o644);
    save("/etc/group", "root:x:0:\nnogroup:x:65534:\n", 0o644);
    const hostKey = path.join(folder, "host_key");
    createKey(hostKey);
    const preliminary = [
      "Port 22222",
      "ListenAddress 127.0.0.1",
      "HostKey " + hostKey,
      "AuthorizedKeysCommand /usr/bin/true",
      "AuthorizedKeysCommandUser nobody",
      "UsePAM no", "PasswordAuthentication no", "PubkeyAuthentication yes",
    ].join("\n") + "\n";
    const trailing = [
      "PermitTTY yes", "AllowTcpForwarding yes",
      "X11Forwarding yes", "AllowAgentForwarding yes",
      "ClientAliveInterval 37", "MaxAuthTries 3",
      "PrintMotd no", "TCPKeepAlive no",
    ].join("\n") + "\n";
    const source = renderOwnerPinnedOfflineSshBootstrap({
      clientPublicKey: createKey(path.join(folder, "client")),
      independentlyPinnedClientSpkiSha256: parsePinnedOpenSshEd25519PublicKey(
        readFileSync(path.join(folder, "client.pub"), "utf8")),
      hostPublicKey: readFileSync(hostKey + ".pub", "utf8"),
      independentlyPinnedHostSpkiSha256: parsePinnedOpenSshEd25519PublicKey(
        readFileSync(hostKey + ".pub", "utf8")),
      reviewedReceiverFiles: [
        "offline-host-transfer-receiver.mjs",
        "lib/offline-ssh-stage-protocol.mjs",
        "lib/offline-ssh-transfer-permit.mjs",
      ].map((name) => ({ path: name, sha256: "a".repeat(64) })),
      reviewedNode22ExecutableSha256: "b".repeat(64),
      unrelatedSshdBaselineSha256: "c".repeat(64),
    });
    save(source.files.sshd_config.path, source.files.sshd_config.contents, 0o644);
    const included = path.join(folder, "with-early-include");
    const before = path.join(folder, "original-with-trailing-globals");
    const badInline = path.join(folder, "bad-inline-control");
    save(before, preliminary + trailing);
    save(included, preliminary + "Include " + source.files.sshd_config.path + "\n" +
      trailing);
    save(badInline, preliminary + source.files.sshd_config.contents + trailing);
    for (const filename of [before, included]) {
      const parsed = run(SSHD, ["-t", "-f", filename]);
      assert.equal(parsed.status, 0, `${filename}: ${parsed.stderr}`);
    }
    const commands = [];
    const contexts = [];
    const unrelatedSnapshots = [];
    const unrelatedCurrent = [];
    for (const principal of ["virki-offline", "root", "nobody", "unrelated-admin"]) {
      for (const tuple of [
        ["localhost", "127.0.0.1", "22"],
        ["remote.example", "192.0.2.54", "22"],
        ["remote.example", "2001:db8::54", "22222"],
      ]) {
        const context = `user=${principal},host=${tuple[0]},addr=${tuple[1]},lport=${tuple[2]}`;
        contexts.push(context);
        const after = run(SSHD, ["-T", "-f", included, "-C", context]);
        assert.equal(after.status, 0, `${context}: ${after.stderr}`);
        if (principal === "virki-offline") {
          assert.equal(verifyRestrictedOfflineSshdEffectiveConfiguration(
            after.stdout.replaceAll("hostkey " + hostKey, "hostkey /etc/ssh/ssh_host_ed25519_key")), true,
          context);
        } else {
          const original = run(SSHD, ["-T", "-f", before, "-C", context]);
          assert.equal(original.status, 0, original.stderr);
          assert.equal(after.stdout, original.stdout,
            `EARLY INCLUDE interfered with unrelated principal/context ${context}`);
          assert.match(after.stdout, /^permittty yes$/mu);
          assert.match(after.stdout, /^clientaliveinterval 37$/mu);
          assert.match(after.stdout, /^authorizedkeyscommand \/usr\/bin\/true$/mu);
          unrelatedSnapshots.push({ context, effective: original.stdout });
          unrelatedCurrent.push(after.stdout);
        }
        commands.push(context);
      }
    }
    assert.equal(commands.length, 12);
    assert.equal(contexts.length, 12);
    assert.deepEqual(unrelatedSnapshots.map((item) => item.context),
      SHARED_SSHD_BASELINE_CONTEXTS);
    assert.equal(verifyUnrelatedSshdEffectiveBaselines({
      version: 1, snapshots: unrelatedSnapshots,
    }, unrelatedCurrent), true);
    // Positive-control sensitivity: a malformed INLINE Match in the main
    // file, rather than the proper Include boundary, must not be mistaken
    // for unchanged unrelated users.
    const direct = run(SSHD, ["-T", "-f", badInline,
      "-C", "user=root,host=localhost,addr=127.0.0.1,lport=22222"]);
    const original = run(SSHD, ["-T", "-f", before,
      "-C", "user=root,host=localhost,addr=127.0.0.1,lport=22222"]);
    assert.equal(original.status, 0, original.stderr);
    assert.ok(direct.status !== 0 || direct.stdout !== original.stdout,
      "test control did not detect inline Match context spillover");
  });
test("isolated real sshd + root sudoers accepts four selectors, rejects shell and arbitrary sudo", onlyFixture, async (t) => {
  const fixtureRoot = mkdtempSync("/tmp/virki-offline-ssh-e2e-");
  t.after(() => rmSync(fixtureRoot, { recursive: true, force: true }));
  const clientKey = path.join(fixtureRoot, "id_ed25519");
  const knownHostsPath = path.join(fixtureRoot, "known_hosts");
  // No host /etc, /run, /usr/local/lib, SSH keys, sudoers, or user account
  // changes exist outside this mount namespace. Private keys remain tmpfs.
  mkdirSync("/etc/ssh/virki-offline", { recursive: true, mode: 0o755 });
  mkdirSync("/etc/ssh/sshd_config.d", { recursive: true, mode: 0o755 });
  mkdirSync("/etc/sudoers.d", { recursive: true, mode: 0o755 });
  mkdirSync("/etc/pam.d", { recursive: true, mode: 0o755 });
  // Test-only PAM modules confined to isolated /etc; no real authentication
  // or WSL host policy is altered. The sudoers itself remains exact.
  save("/etc/pam.d/sudo", [
    "#%PAM-1.0",
    "auth required pam_permit.so",
    "account required pam_permit.so",
    "session required pam_permit.so",
    "",
  ].join("\n"), 0o644);
  // WSL's sudo-rs/visudo install uses /etc/alternatives symlinks; these
  // alternatives live ONLY in the fixture tmpfs, never the real OS /etc.
  mkdirSync("/etc/alternatives", { recursive: true, mode: 0o755 });
  symlinkSync("/usr/lib/cargo/bin/sudo", "/etc/alternatives/sudo");
  symlinkSync("/usr/lib/cargo/bin/visudo", "/etc/alternatives/visudo");
  mkdirSync("/run/sshd", { recursive: true, mode: 0o755 });
  mkdirSync("/usr/local/lib/virki/offline-transfer", { recursive: true, mode: 0o755 });
  save("/etc/passwd", [
    "root:x:0:0:root:/root:/bin/sh",
    "virki-offline:x:1001:1001:offline:/tmp:/bin/sh",
    "sshd:x:102:65534:sshd:/run/sshd:/usr/sbin/nologin",
    "_sshd:x:102:65534:sshd:/run/sshd:/usr/sbin/nologin",
    "",
  ].join("\n"), 0o644);
  save("/etc/group", ["root:x:0:", "virki-offline:x:1001:",
    "nogroup:x:65534:", ""].join("\n"), 0o644);
  save("/etc/shadow", ["root:$6$dummy$notahash:20000:0:99999:7:::",
    "virki-offline:$6$dummy$notahash:20000:0:99999:7:::",
    "sshd:!:20000:0:99999:7:::", "_sshd:!:20000:0:99999:7:::", ""].join("\n"));
  save("/etc/sudoers", [
    "Defaults env_reset",
    "root ALL=(ALL:ALL) ALL",
    "#includedir /etc/sudoers.d",
    "",
  ].join("\n"), 0o440);
  const client = createKey(clientKey);
  const host = createKey("/etc/ssh/ssh_host_ed25519_key");
  const pins = {
    clientPublicKey: client,
    independentlyPinnedClientSpkiSha256: parsePinnedOpenSshEd25519PublicKey(client),
    hostPublicKey: host,
    independentlyPinnedHostSpkiSha256: parsePinnedOpenSshEd25519PublicKey(host),
    reviewedReceiverFiles: [
      "offline-host-transfer-receiver.mjs",
      "lib/offline-ssh-stage-protocol.mjs",
      "lib/offline-ssh-transfer-permit.mjs",
    ].map((name) => ({ path: name, sha256: "a".repeat(64) })),
    reviewedNode22ExecutableSha256: hash(readFileSync("/usr/bin/node")),
    unrelatedSshdBaselineSha256: "c".repeat(64),
  };
  const blueprint = renderOwnerPinnedOfflineSshBootstrap(pins);
  save(blueprint.files.authorized_keys.path, blueprint.files.authorized_keys.contents, 0o644);
  save(blueprint.files.sudoers.path, blueprint.files.sudoers.contents, 0o440);
  assert.equal(inspectOwnerPinnedSshHostKey(host, pins.independentlyPinnedHostSpkiSha256).status,
    "DEDICATED_HOST_KEY_MATCHED_NONAUTHORIZING");
  const hostPublicLocation = "/etc/ssh/ssh_host_ed25519_key.pub";
  const hostPrivateLocation = "/etc/ssh/ssh_host_ed25519_key";
  const originalHostPrivateBytes = readFileSync(hostPrivateLocation);
  save(hostPublicLocation, createKey(path.join(fixtureRoot, "other_host")), 0o644);
  assert.throws(() => inspectOwnerPinnedSshHostKey(host,
    pins.independentlyPinnedHostSpkiSha256), /refused/u);
  save(hostPublicLocation, host + "\n", 0o644);
  // Replacing the actual PRIVATE host key but preserving a pinned .pub
  // must also fail; a .pub-only pin is not proof of sshd's wire identity.
  save(hostPrivateLocation, readFileSync(path.join(fixtureRoot, "other_host")), 0o600);
  assert.throws(() => inspectOwnerPinnedSshHostKey(host,
    pins.independentlyPinnedHostSpkiSha256), /refused/u);
  save(hostPrivateLocation, originalHostPrivateBytes, 0o600);
  assert.equal(inspectOwnerPinnedSshHostKey(host,
    pins.independentlyPinnedHostSpkiSha256).deployAuthorized, false);
  const gate = `import {spawnSync} from "node:child_process";
    const original = process.env.SSH_ORIGINAL_COMMAND;
    const names = {"offline-receive-v1":null,"offline-probe-v1":"--read-probe",
      "offline-docker-v1":"--read-docker","offline-identity-v1":"--read-identity"};
    if (process.argv.length===3 && process.argv[2]==="--gate" && process.getuid()===1001) {
      if (!Object.hasOwn(names,original)) process.exit(33);
      const selector=names[original];
      const args=["-n","-u","root","--","/usr/bin/node",${JSON.stringify(FILE)},
        ...(selector===null?[]:[selector])];
      const result=spawnSync("/usr/bin/sudo",args,{stdio:"inherit",shell:false});
      process.exit(result.status===0?0:34);
    }
    if (process.getuid()===0 && process.env.SUDO_USER==="virki-offline" &&
        /^1001$/.test(process.env.SUDO_UID??"") &&
        ["", "--read-probe","--read-docker","--read-identity"]
          .includes(process.argv[2]??"") &&
        process.argv.length<4) {
      process.stdout.write("SSH_SUDO_FIXED:"+String(process.argv[2]??"receive"));
    } else process.exit(35);
  `;
  save(FILE, gate, 0o644);
  const port = 22222;
  // REGRESSION: Include occurs EARLY, then ordinary global directives
  // CONTINUE AFTER it. Comparing against a config with the same prelude and
  // tail but WITHOUT the Include catches Match scope leaking past EOF.
  // A synthetic ambient AuthorizedKeysCommand must also be shadowed for
  // virki-offline without changing ordinary principals.
  const prelude = [
    "Port 22222", "ListenAddress 127.0.0.1",
    "HostKey /etc/ssh/ssh_host_ed25519_key",
    "PidFile /run/virki-sshd-fixture.pid",
    "UsePAM no", "PermitRootLogin no", "StrictModes yes",
    "AuthorizedKeysCommand /usr/bin/true",
    "AuthorizedKeysCommandUser nobody",
    "PubkeyAuthentication yes", "PasswordAuthentication no",
    "KbdInteractiveAuthentication no", "LogLevel DEBUG3",
  ].join("\n") + "\n";
  const trailingGlobals = [
    "PermitTTY yes",
    "AllowTcpForwarding yes",
    "AllowAgentForwarding yes",
    "X11Forwarding yes",
    "ClientAliveInterval 37",
    "MaxAuthTries 3",
    "PrintMotd no",
    "TCPKeepAlive no",
  ].join("\n") + "\n";
  const shared = prelude + trailingGlobals;
  const baselinePath = path.join(fixtureRoot, "shared-baseline.config");
  save(baselinePath, shared);
  const config = prelude + "Include " + blueprint.files.sshd_config.path + "\n" +
    trailingGlobals;
  assert.equal(config.indexOf("Include "), prelude.length);
  assert.ok(config.indexOf("PermitTTY yes") > config.indexOf("Include "));
  const configPath = path.join(fixtureRoot, "sshd.config");
  // The include must contain ONLY the generated Match, not the main config.
  save(blueprint.files.sshd_config.path, blueprint.files.sshd_config.contents, 0o644);
  save(configPath, config);
  const validated = run(SSHD, ["-t", "-f", configPath]);
  assert.equal(validated.status, 0, validated.stderr);
  for (const principal of ["virki-offline", "root", "unrelated-admin", "nobody"]) {
    for (const context of [
      `user=${principal},host=localhost,addr=127.0.0.1,lport=22222`,
      `user=${principal},host=remote.example,addr=192.0.2.54,lport=22`,
      `user=${principal},host=remote.example,addr=2001:db8::54,lport=22222`,
    ]) {
      const effective = run(SSHD, ["-T", "-f", configPath, "-C", context]);
      assert.equal(effective.status, 0, `${context}: ${effective.stderr}`);
      if (principal === "virki-offline") {
        assert.equal(verifyRestrictedOfflineSshdEffectiveConfiguration(effective.stdout),
          true, context);
        assert.match(effective.stdout, /^authorizedkeyscommand none$/mu);
        assert.match(effective.stdout, /^permittty no$/mu);
      } else {
      const baseline = run(SSHD, ["-T", "-f", baselinePath,
        "-C", context]);
      assert.equal(baseline.status, 0, `${context}: ${baseline.stderr}`);
      assert.equal(effective.stdout, baseline.stdout,
        `EARLY Match Include altered trailing globals for unrelated ${context}`);
      assert.match(effective.stdout, /^permittty yes$/mu);
      assert.match(effective.stdout, /^allowtcpforwarding yes$/mu);
      assert.match(effective.stdout, /^clientaliveinterval 37$/mu);
      }
    }
  }
  const sudoChecked = run("/usr/sbin/visudo", ["-c", "-f", "/etc/sudoers.d/virki-offline"]);
  assert.equal(sudoChecked.status, 0, sudoChecked.stderr + " " + sudoChecked.error?.message);
  const sudoForbidden = run("/usr/bin/sudo", ["-n", "-U", "virki-offline", "-l"]);
  assert.equal(sudoForbidden.status, 0, sudoForbidden.stderr);
  assert.doesNotMatch(sudoForbidden.stdout, /\(ALL\) NOPASSWD: ALL/u);
  save(knownHostsPath,
    `[127.0.0.1]:${port} ${host.split(/\s+/u).slice(0, 2).join(" ")}\n`, 0o600);
  const daemonLog = path.join(fixtureRoot, "sshd.log");
  const daemon = spawn(SSHD, ["-D", "-d", "-E", daemonLog, "-f", configPath], {
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  daemon.stderr.on("data", (buffer) => { stderr += buffer.toString(); });
  t.after(() => { if (daemon.exitCode === null) daemon.kill("SIGTERM"); });
  await new Promise((resolve) => setTimeout(resolve, 250));
  assert.equal(daemon.exitCode, null, stderr);
  const connect = (original) => run("/usr/bin/ssh", [
    "-F", "/dev/null", "-p", String(port),
    "-i", clientKey,
    "-o", "StrictHostKeyChecking=yes",
    "-o", "UserKnownHostsFile=" + knownHostsPath,
    "-o", "IdentitiesOnly=yes", "-o", "PasswordAuthentication=no",
    "-o", "KbdInteractiveAuthentication=no", "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=3", "-T",
    "virki-offline@127.0.0.1", original,
  ]);
  for (const name of [
    "offline-probe-v1", "offline-docker-v1", "offline-identity-v1",
    "offline-receive-v1",
  ]) {
    const response = connect(name);
    assert.equal(response.status, 0, `${name}: ${response.stderr} ${stderr}
      ${existsSync(daemonLog) ? readFileSync(daemonLog, "utf8").slice(-4500) : "no sshd log"}`);
    assert.match(response.stdout, /^SSH_SUDO_FIXED:/u);
  }
  for (const forbidden of ["id", "bash -i", "offline-probe-v1; id",
    "offline-probe-v1 --extra"]) {
    const response = connect(forbidden);
    assert.notEqual(response.status, 0, `unauthorized SSH command ${forbidden} succeeded`);
    assert.doesNotMatch(response.stdout, /SSH_SUDO_FIXED/u);
  }
});
