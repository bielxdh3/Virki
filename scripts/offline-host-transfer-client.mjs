import { spawn, spawnSync } from "node:child_process";
import { closeSync, constants, fstatSync, lstatSync, openSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { once } from "node:events";
import {
  buildPinnedOfflineSshOptions, prepareVerifiedOfflineTransportPlan,
  validateOfflineSshConfiguration, loadPinnedOfflineTransferAuthority,
} from "./offline-production-transport.mjs";
import { isValidProductionConfig } from "./lib/production-config.mjs";
import { streamOfflineStageToWritable } from "./lib/offline-ssh-stage-protocol.mjs";
import { OFFLINE_SSH_LOGIN, requireIndependentlySignedOfflineSshTransfer } from "./lib/offline-ssh-transfer-permit.mjs";

const SSH = "/usr/bin/ssh";
const IDENTITY = "/etc/virki/offline-transfer/ssh-identity";
const FIXED_REMOTE_COMMAND = "offline-receive-v1";
const USER = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/u;
const SHA = /^[a-f0-9]{64}$/u;
const REV = /^[a-f0-9]{40}$/u;
function need(ok, why) { if (!ok) throw new Error("Offline host SSH transfer refused: " + why); }
function same(a, b) {
  return ["dev", "ino", "uid", "mode", "nlink", "size", "mtimeNs", "ctimeNs"]
    .every((key) => a[key] === b[key]);
}
function checkBinaryAndIdentity() {
  need(process.platform === "linux" && process.getuid?.() === 0 &&
    Number.isInteger(constants.O_NOFOLLOW), "owner root Linux client required");
  const binary = lstatSync(SSH);
  need(binary.isFile() && binary.uid === 0 && (binary.mode & 0o022) === 0,
  "root-protected SSH binary required");
  need(realpathSync.native(IDENTITY) === IDENTITY, "SSH identity path aliased");
  const before = lstatSync(IDENTITY, { bigint: true });
  need(before.isFile() && before.uid === 0n && before.nlink === 1n &&
    (before.mode & 0o7777n) === 0o600n, "independent owner SSH identity unavailable");
  const fd = openSync(IDENTITY, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    need(same(before, fstatSync(fd, { bigint: true })) &&
      same(before, lstatSync(IDENTITY, { bigint: true })),
    "SSH identity inode changed");
  } finally { closeSync(fd); }
}
/** Safe construction only; the actual receiver is a separately installed forced command. */
export function buildPinnedOfflineReceiverSshArgs({ trustedDirectory, config }) {
  need(typeof trustedDirectory === "string" && path.isAbsolute(trustedDirectory) &&
    config && isValidProductionConfig(config) && USER.test(config.sshUser ?? "") &&
    config.sshUser === OFFLINE_SSH_LOGIN,
  "untrusted SSH endpoint or fixed restricted SSH login mismatch");
  return Object.freeze([
    ...buildPinnedOfflineSshOptions(trustedDirectory, config),
    "-o", "HostKeyAlgorithms=ssh-ed25519",
    "-o", "PreferredAuthentications=publickey",
    "-o", "PasswordAuthentication=no",
    "-o", "RequestTTY=no", "-T",
    "-o", "ConnectTimeout=15",
    "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2",
    "-o", "KbdInteractiveAuthentication=no",
    "-o", "NumberOfPasswordPrompts=0",
    "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
    "-i", IDENTITY,
    "--", config.sshAlias, FIXED_REMOTE_COMMAND,
  ]);
}
function exactReceipt(result, expected) {
  need(result && typeof result === "object" && !Array.isArray(result) &&
    Object.keys(result).length === 6 &&
    result.status === "HOST_OWNER_SIGNED_PRIVATE_STAGE_VERIFIED" &&
    /^candidate-[a-f0-9]{32}$/u.test(result.stageName) &&
    result.fileCount === 11 && result.manifestSha256 === expected &&
    result.transferAuthorized === false && result.deployAuthorized === false,
  "remote authenticated staging receipt invalid");
  return Object.freeze(result);
}

async function sendOfflineStageOverPinnedSsh({
  candidateDirectory, trustedDirectory, config, manifestSha256, envelopeSha256, signedPermit,
}) {
  checkBinaryAndIdentity();
  need(SHA.test(manifestSha256) && SHA.test(envelopeSha256), "independently accepted signed envelope required");
  const args = buildPinnedOfflineReceiverSshArgs({ trustedDirectory, config });
  const check = spawnSync(SSH, [...args.slice(0, -3), "-G", config.sshAlias], {
    shell: false, encoding: "utf8", timeout: 10_000, maxBuffer: 128 * 1024,
  });
  need(check.status === 0, "pinned OpenSSH resolver unavailable");
  validateOfflineSshConfiguration(check.stdout, config);
  // Host key is authenticated by StrictHostKeyChecking=yes and a root-owned
  // one-line known_hosts file; no prompt, agent, proxy, shell or SCP involved.
  const child = spawn(SSH, args, {
    shell: false, stdio: ["pipe", "pipe", "ignore"], windowsHide: true,
  });
  const stdout = [];
  let received = 0;
  child.stdout.on("data", (part) => {
    received += part.length;
    if (received > 4096) child.kill();
    else stdout.push(part);
  });
  const completion = once(child, "close");
  child.stdin.on("error", () => { /* remote early rejection is reported by SSH exit */ });
  try {
    await streamOfflineStageToWritable({
      candidateDirectory, writable: child.stdin,
      expectedManifestSha256: manifestSha256, expectedEnvelopeSha256: envelopeSha256,
      signedPermit,
    });
    let finalTimeout;
    let result;
    try {
      result = await Promise.race([
        completion,
        new Promise((_, reject) => {
          finalTimeout = setTimeout(() => reject(new Error("SSH staging receipt timed out")), 90_000);
        }),
      ]);
    } finally { clearTimeout(finalTimeout); }
    const [code, signal] = result;
    need(code === 0 && signal === null && received <= 4096, "pinned receiver rejected staged bytes");
    let receipt;
    try { receipt = JSON.parse(Buffer.concat(stdout).toString("utf8").trim()); }
    catch { need(false, "malformed native receiver receipt"); }
    return exactReceipt(receipt, manifestSha256);
  } catch (error) {
    child.kill();
    await completion.catch(() => undefined);
    throw error;
  }
}

/**
 * The owner-signed, short-lived root-installed transfer permit is a distinct
 * SSH-stage authority. It never authorizes native release or activation.
 * No caller may inject permission, SSH credentials, host or remote command.
 */
export async function transferOfflineSignedCandidate(request = {}) {
  need(request && typeof request === "object" && !Array.isArray(request) &&
    Object.keys(request).length === 3 &&
    ["candidateDirectory", "trustedDirectory", "repositoryRoot"].every(
      (key) => Object.hasOwn(request, key)), "exact three path inputs required");
  const plan = await prepareVerifiedOfflineTransportPlan(request);
  need(plan.status === "PRETRANSFER_INSPECTED_DEPLOY_BLOCKED" &&
    REV.test(plan.revision) && SHA.test(plan.signedManifestSha256),
  "local owner-signed plan invalid");
  need(plan.transferAuthorized === false && plan.deployAuthorized === false,
  "read-only preflight must not claim premature transfer authority");
  const authority = loadPinnedOfflineTransferAuthority(request.trustedDirectory);
  need(authority.policy.expectedRevision === plan.revision &&
    authority.config.host === plan.host && Number(authority.config.port) === plan.port,
  "operator transport root changed after preflight");
  const permit = requireIndependentlySignedOfflineSshTransfer({ authority, plan });
  need(permit.transferAuthorized === true && permit.deployAuthorized === false &&
    permit.manifestSha256 === plan.signedManifestSha256, "explicit owner transfer permit rejected");
  return sendOfflineStageOverPinnedSsh({
    candidateDirectory: request.candidateDirectory,
    trustedDirectory: request.trustedDirectory,
    config: authority.config,
    manifestSha256: plan.signedManifestSha256,
    envelopeSha256: plan.signedEnvelopeSha256,
    signedPermit: {
      permitBytes: permit.permitBytes, signatureBytes: permit.signatureBytes,
    },
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const valid = args.length === 6 && args[0] === "--candidate" &&
    args[2] === "--trust" && args[4] === "--repository";
  if (!valid) {
    process.stderr.write("Usage: --candidate ABS --trust ABS --repository ABS\n");
    process.exitCode = 2;
  } else {
    try {
      const result = await transferOfflineSignedCandidate({
        candidateDirectory: args[1], trustedDirectory: args[3], repositoryRoot: args[5],
      });
      process.stdout.write(JSON.stringify(result) + "\n");
      // Local transfer does not authorize deployment; successful staging
      // still exits non-zero so automation cannot mistake it for release.
      process.exitCode = 2;
    } catch {
      process.stderr.write("Owner-pinned SSH transfer refused; no release authorized.\n");
      process.exitCode = 2;
    }
  }
}
