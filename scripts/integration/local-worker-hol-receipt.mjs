// Separate Windows-only receipt directory for the local HOL proof. The shared
// Docker-recovery ACL helper intentionally rejects even an execute-only Windows
// app-capability ACE on the user's profile. Here, verify that the profile has
// NO FOREIGN WRITE permission and then require an exclusively owner-controlled
// private child directory and receipt file. Do not relax the shared helper.
import { execFileSync } from "node:child_process";
import { lstatSync, mkdirSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const ICACLS = "C:\\Windows\\System32\\icacls.exe";
const WHOAMI = "C:\\Windows\\System32\\whoami.exe";
const root = path.join(os.homedir(), ".virki-private-local-hol");

function ordinary(location, file = false) {
  const state = lstatSync(location);
  if (state.isSymbolicLink() || (file ? !state.isFile() : !state.isDirectory())) {
    throw new Error("Local HOL receipt location is a symlink, reparse point or unexpected type.");
  }
}

function powerShell(script) {
  const result = execFileSync(POWERSHELL, [
    "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script
  ], { encoding: "utf8", windowsHide: true, timeout: 15_000, stdio: "pipe" });
  if (result.trim() !== "PRIVATE_HOL_RECEIPT") throw new Error("Local HOL ACL proof did not complete.");
}

function verifyAcl(location, allowForeignTraverse) {
  const quoted = location.replaceAll("'", "''");
  const script = [
    `$p = '${quoted}'`,
    "$ErrorActionPreference='Stop'",
    "$who = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
    "$allowed = @($who, 'S-1-5-18', 'S-1-5-32-544')",
    "$acl = Get-Acl -LiteralPath $p -ErrorAction Stop",
    "$owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value",
    "if ($allowed -notcontains $owner) { throw 'Foreign owner of local HOL receipt.' }",
    "$unsafe = [System.Security.AccessControl.FileSystemRights]::Write -bor",
    "  [System.Security.AccessControl.FileSystemRights]::Delete -bor",
    "  [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor",
    "  [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor",
    "  [System.Security.AccessControl.FileSystemRights]::TakeOwnership",
    "foreach ($ace in $acl.Access) {",
    "  if ($ace.AccessControlType -ne 'Allow') { continue }",
    "  $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value",
    "  if ($allowed -contains $sid) { continue }",
    ...(allowForeignTraverse
      ? ["  if (($ace.FileSystemRights -band $unsafe) -ne 0) { throw 'Foreign writer can alter HOL receipt parent.' }"]
      : ["  throw 'Foreign access to local HOL private receipt.'"]),
    "}",
    "[Console]::Out.Write('PRIVATE_HOL_RECEIPT')"
  ].join("\n");
  powerShell(script);
}

export function privateLocalHolReceiptDirectory() {
  if (process.platform !== "win32") throw new Error("Local HOL receipts require Windows.");
  return root;
}

export function ensurePrivateLocalHolReceiptDirectory() {
  if (process.platform !== "win32") throw new Error("Local HOL receipts require Windows.");
  ordinary(os.homedir());
  // Read-only or traverse-only foreign ACEs on the home profile cannot create,
  // replace, rename, delete or take ownership of our private child.
  verifyAcl(os.homedir(), true);
  try {
    ordinary(root);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    mkdirSync(root, { recursive: false });
    ordinary(root);
    const user = execFileSync(WHOAMI, [], {
      encoding: "utf8", windowsHide: true, timeout: 10_000
    }).trim();
    if (!user || /[\r\n]/u.test(user)) throw new Error("Local HOL receipt owner name invalid.", { cause: error });
    execFileSync(ICACLS, [root, "/inheritance:r", "/grant:r", `${user}:(OI)(CI)F`], {
      windowsHide: true, timeout: 15_000, stdio: "pipe"
    });
  }
  ordinary(root);
  verifyAcl(root, false);
}

export function assertPrivateLocalHolReceiptFile(file) {
  if (process.platform !== "win32" || path.dirname(file) !== root ||
      !/^email-hol-[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}\.jsonl$/u.test(path.basename(file))) {
    throw new Error("Local HOL receipt escaped the private directory.");
  }
  ordinary(file, true);
  ensurePrivateLocalHolReceiptDirectory();
  verifyAcl(file, false);
}
