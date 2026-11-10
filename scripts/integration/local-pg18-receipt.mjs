// Narrow Windows-only receipt gate for the owned, disposable PG18 recovery
// proof. Do not relax the shared Docker receipt policy for other workflows.
// The home directory may have foreign read/execute ACEs only when NO foreign
// principal can write, delete or take ownership. The child/leaf must have NO
// foreign ALLOW ACE at all.
import { execFileSync } from "node:child_process";
import { lstatSync, mkdirSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { assertPrivateEvidenceFile, ensurePrivateEvidenceDirectory,
  ownerEvidenceDirectory } from "../lib/disposable-docker-receipt-security.mjs";

export const PG18_WINDOWS_POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const ICACLS = "C:\\Windows\\System32\\icacls.exe";
const WHOAMI = "C:\\Windows\\System32\\whoami.exe";
const home = os.homedir();
const privateDirectory = path.join(home, ".virki-private-local-pg18");
const RECEIPT_NAME = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}\.jsonl$/u;

function ordinary(location, file = false) {
  const state = lstatSync(location);
  if (state.isSymbolicLink() || (file ? !state.isFile() : !state.isDirectory())) {
    throw new Error("Private PG18 receipt location is a link, reparse point or unexpected type.");
  }
}

// Exported for nonmutating source and synthetic-ACL regression tests.
// The exact generated command is used by the live ACL verifier, so tests
// exercise its actual policy instead of a second JavaScript interpretation.
export function pg18WindowsAclProbeScript(location, { parent = false, file = false } = {}) {
  if (typeof location !== "string" || !location || /[\r\n\0]/u.test(location)) {
    throw new Error("Invalid PG18 receipt location.");
  }
  const quoted = location.replaceAll("'", "''");
  return [
    "$ErrorActionPreference='Stop'",
    `$p = '${quoted}'`,
    "$who = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
    "$allowed = @($who, 'S-1-5-18', 'S-1-5-32-544')",
    "$entry = Get-Item -LiteralPath $p -Force -ErrorAction Stop",
    "if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'PG18 receipt reparse point refused' }",
    `if ($entry.PSIsContainer -ne ${file ? "$false" : "$true"}) { throw 'PG18 receipt type mismatch' }`,
    "$acl = Get-Acl -LiteralPath $p -ErrorAction Stop",
    "$owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value",
    "if ($allowed -notcontains $owner) { throw 'PG18 receipt foreign owner' }",
    "$unsafe = [System.Security.AccessControl.FileSystemRights]::Write -bor",
    "  [System.Security.AccessControl.FileSystemRights]::Delete -bor",
    "  [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor",
    "  [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor",
    "  [System.Security.AccessControl.FileSystemRights]::TakeOwnership",
    "foreach ($ace in $acl.Access) {",
    "  if ($ace.AccessControlType -ne 'Allow') { continue }",
    "  $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value",
    "  if ($allowed -contains $sid) { continue }",
    ...(parent
      ? ["  if (($ace.FileSystemRights -band $unsafe) -ne 0) { throw 'PG18 receipt foreign writer on parent' }"]
      : ["  throw 'PG18 receipt private child or leaf permits foreign access'"]),
    "}",
    "[Console]::Out.Write('PRIVATE_PG18_RECEIPT')"
  ].join("\n");
}

function checkWindowsAcl(location, options) {
  const observed = execFileSync(PG18_WINDOWS_POWERSHELL, [
    "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
    pg18WindowsAclProbeScript(location, options)
  ], { encoding: "utf8", windowsHide: true, timeout: 15_000, stdio: "pipe" });
  if (observed.trim() !== "PRIVATE_PG18_RECEIPT") {
    throw new Error("PG18 receipt ACL verifier did not return its exact acceptance marker.");
  }
}

export function pg18ReceiptDirectory(repoRoot) {
  return process.platform === "win32" ? privateDirectory : ownerEvidenceDirectory(repoRoot, "recovery");
}

export function ensurePrivatePg18ReceiptDirectory(location) {
  if (process.platform !== "win32") {
    ensurePrivateEvidenceDirectory(location);
    return;
  }
  if (location !== privateDirectory) throw new Error("PG18 receipt directory escaped its private location.");
  ordinary(home);
  // Only the HOME parent's read/traverse ACEs may be foreign.
  checkWindowsAcl(home, { parent: true });
  try {
    ordinary(privateDirectory);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    mkdirSync(privateDirectory, { recursive: false });
    ordinary(privateDirectory);
    const user = execFileSync(WHOAMI, [], {
      encoding: "utf8", windowsHide: true, timeout: 10_000
    }).trim();
    if (!user || /[\r\n]/u.test(user)) {
      throw new Error("PG18 receipt user identity invalid.", { cause: error });
    }
    execFileSync(ICACLS, [
      privateDirectory, "/inheritance:r", "/grant:r", `${user}:(OI)(CI)F`
    ], { windowsHide: true, timeout: 15_000, stdio: "pipe" });
  }
  ordinary(privateDirectory);
  checkWindowsAcl(privateDirectory);
}

export function assertPrivatePg18ReceiptFile(filename) {
  if (process.platform !== "win32") {
    assertPrivateEvidenceFile(filename);
    return;
  }
  if (path.dirname(filename) !== privateDirectory ||
      !RECEIPT_NAME.test(path.basename(filename))) {
    throw new Error("PG18 receipt file escaped its private location.");
  }
  ordinary(filename, true);
  ensurePrivatePg18ReceiptDirectory(privateDirectory);
  checkWindowsAcl(filename, { file: true });
}
