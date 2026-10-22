import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  compareUntrustedDockerInfoForPreview, inspectNativeIsolatedDockerDaemon,
  previewIsolatedDaemonEvidenceForTests, previewSyntheticProcDaemonForTests,
} from "./isolated-docker-daemon-identity.mjs";

// Every fixture is in memory. These tests never contact a real Docker socket,
// mount a Docker daemon, write host /etc, or create a privileged container.
const hash = (character) => character.repeat(64);
const socket = "/run/virki-offline-import/docker.sock";
const policy = Object.freeze({
  version: 1, mode: "virki-isolated-daemon-owner-pin-v1",
  cliSha256: hash("a"), daemonSha256: hash("b"),
  daemonPid: 3240, daemonStartTicks: "110005",
  socketKernelInode: "98765",
  daemonCgroup: "0::/virki-offline-import.slice",
  mountNamespace: "mnt:[10001]", netNamespace: "net:[10002]",
  pidNamespace: "pid:[10003]",
});
const bytes = () => Buffer.from(JSON.stringify(policy));
const validEvidence = () => ({
  cliSha256: policy.cliSha256, daemonSha256: policy.daemonSha256,
  daemonPid: policy.daemonPid, daemonStartTicks: policy.daemonStartTicks,
  socketKernelInode: policy.socketKernelInode,
  socketOwnedByDaemon: true, daemonCgroup: policy.daemonCgroup,
  mountNamespace: policy.mountNamespace, netNamespace: policy.netNamespace,
  pidNamespace: policy.pidNamespace, procRootOwned: true,
  socketFileRootPrivate: true, dataRootPrivate: true, execRootPrivate: true,
  namespacesDifferFromInspector: true,
  daemonUidRoot: true, daemonCmdlineExact: true,
  kernelPeerCredentials: false, independentlyAttestedLifecycle: false,
});
function stat(start = policy.daemonStartTicks) {
  // The process name deliberately contains spaces and parentheses; find the
  // last ')' and take field 22 rather than splitting /proc/<pid>/stat naively.
  const trailing = Array.from({ length: 35 }, (_, index) =>
    index === 19 ? start : "1");
  return `${policy.daemonPid} (dockerd (test) worker) ${trailing.join(" ")}\n`;
}
function unix(inode = policy.socketKernelInode, pathname = socket) {
  return [
    "Num RefCount Protocol Flags Type St Inode Path",
    `00000000: 00000002 00000000 00010000 0001 01 ${inode} ${pathname}`,
    "",
  ].join("\n");
}
const args = [
  "/run/virki-offline-import/dockerd",
  "--host=unix://" + socket,
  "--data-root=/var/lib/virki/offline-import-daemon-data",
  "--exec-root=/run/virki-offline-import/exec",
  "--config-file=/dev/null",
  "--iptables=false",
  "--ip6tables=false",
  "--bridge=none",
  "--userland-proxy=false",
];
function synthetic() {
  return {
    cliSha256: policy.cliSha256, daemonSha256: policy.daemonSha256,
    daemonPid: policy.daemonPid,
    statBefore: stat(), statAfter: stat(),
    unixBefore: unix(), unixAfter: unix(),
    fdLinksBefore: ["pipe:[4]", "socket:[98765]"],
    fdLinksAfter: ["pipe:[4]", "socket:[98765]"],
    status: "Name:\tdockerd\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n",
    cmdline: Buffer.from(args.join("\0") + "\0"),
    cgroup: policy.daemonCgroup,
    mountNamespace: policy.mountNamespace, netNamespace: policy.netNamespace,
    pidNamespace: policy.pidNamespace, procRootOwned: true,
    socketFileRootPrivate: true, dataRootPrivate: true,
    execRootPrivate: true, namespacesDifferFromInspector: true,
  };
}
const checked = (evidence = validEvidence(), policyBytes = bytes()) =>
  previewIsolatedDaemonEvidenceForTests({ policyBytes, evidence });
const simulated = (snapshot = synthetic(), policyBytes = bytes()) =>
  previewSyntheticProcDaemonForTests({ policyBytes, snapshot });
const blocked = (result) => {
  assert.equal(result.status, "BLOCKED_DAEMON_PROVENANCE_UNVERIFIED");
  assert.equal(result.dockerLoadAuthorized, false);
  assert.equal(result.deployAuthorized, false);
};
const matched = (result) => {
  assert.equal(result.status, "KERNEL_IDENTITY_MATCHES_PINS_PEER_AND_LIFECYCLE_UNPROVEN");
  assert.equal(result.dockerLoadAuthorized, false);
  assert.equal(result.deployAuthorized, false);
  assert.equal(result.peerVerified, false);
  assert.equal(result.lifecycleVerified, false);
  assert.equal(result.missingProofs.length, 2);
};

test("matching root-owned operator pins and Linux kernel evidence NEVER authorize Docker import", () => {
  matched(checked());
  matched(simulated());
});

test("independent immutable owner policy rejects injected pinsets, versions, duplicate fields and key ordering", () => {
  for (const policyBytes of [
    Buffer.from(JSON.stringify({ ...policy, version: 2 })),
    Buffer.from(JSON.stringify({ ...policy, dockerHost: "unix:///var/run/docker.sock" })),
    Buffer.from(JSON.stringify({ ...policy, cliSha256: "a" })),
    Buffer.from(JSON.stringify({ ...policy, daemonPid: 1 })),
    Buffer.from(JSON.stringify({ ...policy, daemonCgroup: "0::/system.slice/docker.service" })),
    Buffer.from(JSON.stringify({ ...policy, mountNamespace: "mnt:[0]" })),
    Buffer.from(JSON.stringify({ ...policy, netNamespace: "mnt:[10002]" })),
    Buffer.from(JSON.stringify({ ...policy, daemonStartTicks: "0" })),
    Buffer.from(JSON.stringify({ ...policy, socketKernelInode: "0" })),
    Buffer.from(JSON.stringify({ ...policy, mode: "unsafe-force-on" })),
    Buffer.from(JSON.stringify({ ...policy, daemonSha256: hash("C") })),
    Buffer.from(JSON.stringify(policy).replace('"version":1,', '"version":1,"version":1,')),
    Buffer.from(JSON.stringify(policy) + "\n"),
    Buffer.from("{"),
    Buffer.from([0xff, 0xfe]),
    Buffer.alloc(5000),
  ]) blocked(checked(validEvidence(), policyBytes));
  const reordered = {
    mode: policy.mode, version: policy.version,
    ...Object.fromEntries(Object.entries(policy).filter(([name]) =>
      name !== "mode" && name !== "version")),
  };
  blocked(checked(validEvidence(), Buffer.from(JSON.stringify(reordered))));
});

test("falsified root dir/cgroup/PID/restart, socket inode, ELF binary and namespaces cannot pass", () => {
  const counterfeits = [
    { cliSha256: hash("c") }, { daemonSha256: hash("c") },
    { daemonPid: 3241 }, { daemonStartTicks: "110006" },
    { socketKernelInode: "98766" }, { socketOwnedByDaemon: false },
    { daemonCgroup: "0::/system.slice/docker.service" },
    { mountNamespace: "mnt:[999]" }, { netNamespace: "net:[999]" },
    { pidNamespace: "pid:[999]" },
    { procRootOwned: false }, { socketFileRootPrivate: false },
    { dataRootPrivate: false }, { execRootPrivate: false },
    { daemonUidRoot: false }, { daemonCmdlineExact: false },
    { namespacesDifferFromInspector: false },
    { kernelPeerCredentials: true }, { independentlyAttestedLifecycle: true },
    { dockerHost: "unix:///var/run/docker.sock" },
    { deployAuthorized: true },
  ];
  for (const variant of counterfeits) {
    blocked(checked({ ...validEvidence(), ...variant }));
  }
});

test("fake /proc snapshots reject PID reuse, socket holder race, host dockerd and switched namespaces", () => {
  const base = synthetic();
  const fake = [
    { ...base, statAfter: stat("110006") },
    { ...base, statBefore: stat("110006") },
    { ...base, unixAfter: unix("123456") },
    { ...base, unixBefore: unix("123456") },
    { ...base, fdLinksBefore: ["pipe:[4]"] },
    { ...base, fdLinksAfter: ["socket:[123456]"] },
    { ...base, unixBefore: unix("98765", "/var/run/docker.sock") },
    { ...base, unixBefore: unix() + unix() },
    { ...base, unixBefore: unix().replace("00010000", "00000000") },
    { ...base, cmdline: Buffer.from(args.join("\0")) },
    { ...base, cmdline: Buffer.from([
      args[0], "--host=unix:///var/run/docker.sock", ...args.slice(2),
    ].join("\0") + "\0") },
    { ...base, cmdline: Buffer.from([
      ...args.slice(0, 2), "--data-root=/var/lib/docker", ...args.slice(3),
    ].join("\0") + "\0") },
    { ...base, status: base.status.replace("Uid:\t0\t0\t0\t0", "Uid:\t0\t1000\t0\t0") },
    { ...base, status: base.status.replace("Gid:\t0\t0\t0\t0", "Gid:\t0\t0\t1000\t0") },
    { ...base, cgroup: "0::/system.slice/docker.service" },
    { ...base, mountNamespace: "mnt:[9000]" },
    { ...base, netNamespace: "net:[9000]" },
    { ...base, pidNamespace: "pid:[9000]" },
    { ...base, daemonPid: 3241 },
    { ...base, socketFileRootPrivate: false },
    { ...base, dataRootPrivate: false },
    { ...base, execRootPrivate: false },
    { ...base, namespacesDifferFromInspector: false },
    { ...base, fdLinksAfter: [...base.fdLinksAfter, "socket:[98765]"], injection: true },
  ];
  for (const sample of fake) blocked(simulated(sample));
});

test("Docker info self-report may correlate but cannot prove peer or independent daemon lifecycle", () => {
  const info = {
    DockerRootDir: "/var/lib/virki/offline-import-daemon-data",
    Driver: "vfs", CgroupVersion: "2", CgroupDriver: "systemd",
  };
  const result = compareUntrustedDockerInfoForPreview(info);
  assert.equal(result.status, "DOCKER_INFO_CORRELATES_ONLY_NOT_DAEMON_PROVENANCE");
  assert.equal(result.dockerLoadAuthorized, false);
  assert.equal(result.peerVerified, false);
  for (const changed of [
    { DockerRootDir: "/var/lib/docker" },
    { Driver: "overlay2" },
    { CgroupVersion: "1" },
    { CgroupDriver: "cgroupfs" },
    { DockerRootDir: "/var/lib/virki/offline-import-daemon-data", daemonVerified: true },
  ]) blocked(compareUntrustedDockerInfoForPreview({ ...info, ...changed }));
});

test("native inspection refuses non-native environments and does not open Docker, even with caller overrides", () => {
  if (process.platform !== "linux" || process.getuid?.() !== 0) {
    blocked(inspectNativeIsolatedDockerDaemon({}));
  }
  for (const request of [
    { daemonPid: 1 }, { dockerHost: "unix:///var/run/docker.sock" },
    { policyBytes: bytes() }, { dockerInfo: { DockerRootDir: "/var/lib/docker" } },
  ]) blocked(inspectNativeIsolatedDockerDaemon(request));
});

test("verified source imports no Docker command or networking API", () => {
  const source = readFileSync(new URL("./isolated-docker-daemon-identity.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(source, /from "node:(?:child_process|net|http|https)"/u);
  assert.doesNotMatch(source, /(?:spawnSync|execFileSync|createConnection|connect)\s*\(/u);
  assert.match(source, /SO_PEERCRED/u);
  assert.match(source, /dockerLoadAuthorized: false/u);
});
