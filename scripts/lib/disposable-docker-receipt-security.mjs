import { execFileSync } from "node:child_process";
import { lstatSync, mkdirSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const WINDOWS_ICACLS = "C:\\Windows\\System32\\icacls.exe";
const WINDOWS_POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const WINDOWS_WHOAMI = "C:\\Windows\\System32\\whoami.exe";
const SAFE_KIND = /^(?:passkeys|oidc|recovery)$/u;

function ordinaryDirectory(location) {
  const state = lstatSync(location);
  if (!state.isDirectory() || state.isSymbolicLink()) {
    throw new Error("Disposable Docker receipt path is not an ordinary directory.");
  }
}

// Independent of localized Windows account names: inspect SID values, not
// icacls' human-readable output. Only the current user, SYSTEM and the local
// Administrators group may have an ALLOW ACE granting access to this evidence.
function verifyWindowsAcl(location) {
  const escaped = location.replaceAll("'", "''");
  const script = [
    `$p = '${escaped}'`,
    "$who = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
    "$allowed = @($who, 'S-1-5-18', 'S-1-5-32-544')",
    "$acl = Get-Acl -LiteralPath $p -ErrorAction Stop",
    "foreach ($rule in $acl.Access) {",
    "  if ($rule.AccessControlType -ne 'Allow') { continue }",
    "  $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value",
    "  if ($allowed -notcontains $sid) { throw ('Foreign access to private Docker receipt: ' + $sid) }",
    "}",
    "if (($acl.Owner -ne [System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -and",
    "    ($acl.Owner -ne 'BUILTIN\\Administrators')) {",
    "  $ownerSid = (New-Object System.Security.Principal.NTAccount($acl.Owner)).Translate([System.Security.Principal.SecurityIdentifier]).Value",
    "  if ($ownerSid -ne $who -and $ownerSid -ne 'S-1-5-32-544') { throw 'Foreign receipt owner' }",
    "}",
  ].join("\n");
  execFileSync(WINDOWS_POWERSHELL, [
    "-NoProfile", "-NonInteractive", "-Command", script
  ], { windowsHide: true, timeout: 15_000, stdio: "pipe" });
}

function makeWindowsOwnerPrivateDirectory(directory) {
  mkdirSync(directory, { recursive: false });
  ordinaryDirectory(directory);
  const current = execFileSync(WINDOWS_WHOAMI, [], {
    encoding: "utf8", windowsHide: true, timeout: 10_000
  }).trim();
  if (!current || /[\r\n]/u.test(current)) throw new Error("Invalid Windows receipt owner.");
  execFileSync(WINDOWS_ICACLS, [
    directory, "/inheritance:r", "/grant:r", `${current}:(OI)(CI)F`
  ], { windowsHide: true, timeout: 15_000, stdio: "pipe" });
  verifyWindowsAcl(directory);
}

export function ownerEvidenceDirectory(repoRoot, kind) {
  if (!SAFE_KIND.test(kind)) throw new Error("Unreviewed Docker receipt kind.");
  if (process.platform === "win32") {
    return path.join(os.homedir(), ".virki-private-docker-receipts", kind);
  }
  return path.join(repoRoot, ".virki-mission-tmp", `${kind}-docker-recovery`);
}

export function ensurePrivateEvidenceDirectory(location) {
  if (process.platform !== "win32") return;
  const home = os.homedir();
  ordinaryDirectory(home);
  verifyWindowsAcl(home);
  const parent = path.join(home, ".virki-private-docker-receipts");
  if (location !== path.join(parent, "oidc") &&
      location !== path.join(parent, "passkeys") &&
      location !== path.join(parent, "recovery")) {
    throw new Error("Docker receipt directory escaped the private user profile.");
  }
  for (const directory of [parent, location]) {
    try {
      ordinaryDirectory(directory);
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
      makeWindowsOwnerPrivateDirectory(directory);
    }
    ordinaryDirectory(directory);
    verifyWindowsAcl(directory);
  }
}

export function assertPrivateEvidenceFile(filename) {
  if (process.platform !== "win32") return;
  if (path.dirname(filename) !== ownerEvidenceDirectory("", "oidc") &&
      path.dirname(filename) !== ownerEvidenceDirectory("", "passkeys") &&
      path.dirname(filename) !== ownerEvidenceDirectory("", "recovery")) {
    throw new Error("Docker receipt file outside private evidence directory.");
  }
  const state = lstatSync(filename);
  if (!state.isFile() || state.isSymbolicLink()) {
    throw new Error("Docker receipt is not an ordinary file.");
  }
  verifyWindowsAcl(filename);
}
