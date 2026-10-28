import { spawnSync } from "node:child_process";
import { realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { isValidProductionConfig, readProductionConfig } from "./lib/production-config.mjs";
import { SSH_OPTIONS } from "./production-preflight.mjs";

// This measures only publicly observable OS metadata, not the validity of
// owner approval or trusted module bytes. A result NEVER authorizes release.
export const OFFLINE_COMPONENTS = Object.freeze([
  "TRUST_POLICY", "VERIFIER_MODULE", "LEDGER", "ISOLATED_DOCKER_SOCKET",
  "OWNER_BOOTSTRAP",
]);
const BLOCKED = Object.freeze({
  status: "HOST_READINESS_UNVERIFIED", transferAuthorized: false, deployAuthorized: false,
});
const PINNED_SSH_OPTIONS = Object.freeze([
  ...SSH_OPTIONS,
  "-o", "ProxyCommand=none",
  "-o", "ProxyJump=none",
  "-o", "ControlMaster=no",
  "-o", "ControlPath=none",
  "-o", "PermitLocalCommand=no",
  "-o", "ClearAllForwardings=yes",
]);

function pinnedReadOnlySshOptions(config, sshUser) {
  // -F none is essential: Match exec directives execute during ssh -G, even
  // when PermitLocalCommand=no. Never parse an ambient user/system config.
  return ["-F", "none", ...PINNED_SSH_OPTIONS,
    "-o", `HostName=${config.host}`, "-o", `Port=${config.port}`,
    "-o", `User=${sshUser}`, "-o", `HostKeyAlias=${config.sshAlias}`];
}

// OpenSSH -G prints StrictHostKeyChecking=yes as "true" on Windows, and
// often omits disabled proxy options altogether. The CLI hard-pins both
// proxies to "none" and strict key checking before this inspection; verify
// the effective output rather than relying on a platform-specific spelling.
// This is intentionally separate from the stricter release transport policy:
// only an informational read-only check uses this compatibility parser.
function validateReadOnlySshConfiguration(output, config, expectedUser) {
  const fields = new Map();
  for (const line of output.split(/\r?\n/u)) {
    const matched = /^(hostname|port|user|stricthostkeychecking|proxycommand|proxyjump|permitlocalcommand|clearallforwardings|localcommand|localforward|remoteforward|dynamicforward)\s+(.+)$/iu.exec(line.trim());
    if (!matched) continue;
    const name = matched[1].toLowerCase();
    if (fields.has(name)) return false;
    fields.set(name, matched[2].trim());
  }
  const proxyDisabled = (name) => fields.get(name) === undefined || fields.get(name) === "none";
  return fields.get("hostname")?.toLowerCase() === config.host.toLowerCase() &&
    fields.get("port") === String(config.port) &&
    fields.get("user") === expectedUser &&
    ["yes", "true"].includes(fields.get("stricthostkeychecking")) &&
    ["no", "false"].includes(fields.get("permitlocalcommand")) &&
    ["yes", "true"].includes(fields.get("clearallforwardings")) &&
    ["localcommand", "localforward", "remoteforward", "dynamicforward"].every((name) => !fields.has(name)) &&
    proxyDisabled("proxycommand") && proxyDisabled("proxyjump");
}

// Fixed script, never interpolated from remote output, file contents, user
// arguments or release bundle. The configured remote operator need not have
// root privileges: EACCES and missing files BOTH report UNVERIFIED.
const SCRIPT = `set -eu
for descriptor in \
  'TRUST_POLICY|/etc/virki/offline-release/trust-policy.json|regular file|600' \
  'VERIFIER_MODULE|/usr/local/lib/virki/offline-release/infra/offline/trusted-release-coordinator.mjs|regular file|600' \
  'LEDGER|/var/lib/virki/offline-release/ledger.json|regular file|600' \
  'ISOLATED_DOCKER_SOCKET|/run/virki-offline-import/docker.sock|socket|600' \
  'OWNER_BOOTSTRAP|/etc/virki/offline-bootstrap/bootstrap-policy.json|regular file|600'
do
  label=$(printf '%s' "$descriptor" | cut -d '|' -f 1)
  name=$(printf '%s' "$descriptor" | cut -d '|' -f 2)
  expected_type=$(printf '%s' "$descriptor" | cut -d '|' -f 3)
  expected_mode=$(printf '%s' "$descriptor" | cut -d '|' -f 4)
  if observed=$(stat -c '%u|%a|%F' -- "$name" 2>/dev/null); then
    if [ "$observed" = "0|$expected_mode|$expected_type" ]; then
      printf 'VIRKI_OFFLINE_COMPONENT_%s=METADATA_OBSERVED\\n' "$label"
    else
      printf 'VIRKI_OFFLINE_COMPONENT_%s=UNVERIFIED\\n' "$label"
    fi
  else
    printf 'VIRKI_OFFLINE_COMPONENT_%s=UNVERIFIED\\n' "$label"
  fi
done
`;

// The response intentionally lists only the fixed, audited descriptor names.
// A remote alias, text banner, duplicate or reordered response cannot become
// a positive result. No realpath, secret content or environment value is sent.
export async function inspectOfflineHostReadiness({
  config = readProductionConfig(),
  sshUser = config?.sshUser ?? process.env.VIRKI_OFFLINE_SSH_USER,
  execute = (command, args, options = {}) => {
    const result = spawnSync(command, args, {
      shell: false, windowsHide: true, encoding: "utf8",
      input: options.input,
      timeout: 15_000, maxBuffer: 4096,
      stdio: options.input === undefined ? ["ignore", "pipe", "pipe"] : ["pipe", "pipe", "pipe"],
    });
    return { status: result.error || result.signal ? 1 : result.status, stdout: result.stdout ?? "" };
  },
} = {}) {
  try {
    if (!isValidProductionConfig(config) ||
      !/^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$/u.test(config.host) ||
      !/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/u.test(sshUser ?? "")) return BLOCKED;
    const options = pinnedReadOnlySshOptions(config, sshUser);
    const resolved = execute("ssh", ["-G", ...options, config.host]);
    if (resolved.status !== 0 || typeof resolved.stdout !== "string" || resolved.stdout.length > 8192) return BLOCKED;
    if (!validateReadOnlySshConfiguration(resolved.stdout, config, sshUser)) return BLOCKED;

    const remote = execute("ssh", [...options, config.host, "bash -s --"], { input: SCRIPT });
    if (remote.status !== 0 || typeof remote.stdout !== "string" || remote.stdout.length > 512) return BLOCKED;
    const lines = remote.stdout.split(/\r?\n/u);
    if (lines.pop() !== "" || lines.length !== OFFLINE_COMPONENTS.length) return BLOCKED;
    const metadataObserved = [];
    const unverified = [];
    for (const [index, name] of OFFLINE_COMPONENTS.entries()) {
      const prefix = `VIRKI_OFFLINE_COMPONENT_${name}=`;
      if (!lines[index].startsWith(prefix)) return BLOCKED;
      const value = lines[index].slice(prefix.length);
      if (value !== "METADATA_OBSERVED" && value !== "UNVERIFIED") return BLOCKED;
      (value === "METADATA_OBSERVED" ? metadataObserved : unverified).push(name);
    }
    return Object.freeze({
      status: "HOST_COMPONENTS_INSPECTED_ONLY",
      metadataObserved, unverified,
      transferAuthorized: false, deployAuthorized: false,
    });
  } catch {
    // SSH errors can contain private path or host information; do not echo.
    return BLOCKED;
  }
}

const entry = fileURLToPath(import.meta.url);
const invoked = process.argv[1] ? path.resolve(process.argv[1]) : null;
let isEntrypoint = false;
let canonicalEntry = false;
try {
  isEntrypoint = invoked !== null && realpathSync.native(invoked) === realpathSync.native(entry);
  canonicalEntry = isEntrypoint && invoked === entry && realpathSync.native(invoked) === invoked;
} catch { /* missing aliases cannot be executable entrypoints */ }
if (isEntrypoint) {
  const result = canonicalEntry && process.argv.length === 2
    ? await inspectOfflineHostReadiness() : BLOCKED;
  process.stdout.write(JSON.stringify(result) + "\n");
  process.exitCode = result.status === "HOST_COMPONENTS_INSPECTED_ONLY" ? 0 : 1;
}
