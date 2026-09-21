import { mkdirSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  inspectProductionSource,
  ProductionRevisionError,
  runCommand,
} from "./lib/production-revision.mjs";
import {
  PRODUCTION_SSH_ALIAS,
  SSH_OPTIONS,
  runProductionPreflight,
} from "./production-preflight.mjs";
import { runRemoteProductionCommand } from "./production-remote.mjs";

const repositoryRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const tempRoot = path.join(repositoryRoot, ".bielos-mission-tmp");
const archivePath = path.join(tempRoot, "production-source.zip");
const remoteArchivePath = "C:/BielOS/.deploy-tmp/production-source.zip";
const remoteEnvPath = "C:/BielOS/.env";

function encodePowerShell(script) {
  return Buffer.from(script, "utf16le").toString("base64");
}

function runRemotePowerShell(script) {
  return runCommand("ssh", [
    ...SSH_OPTIONS,
    PRODUCTION_SSH_ALIAS,
    "powershell.exe",
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-EncodedCommand",
    encodePowerShell(script),
  ]);
}

function copyFileToRemote(localPath, remotePath) {
  return runCommand("scp", [
    ...SSH_OPTIONS,
    localPath,
    `${PRODUCTION_SSH_ALIAS}:${remotePath}`,
  ]);
}

function requireSuccess(result, message) {
  if (result.status !== 0) throw new ProductionRevisionError("COMMAND_FAILED", message);
}

async function guardedStage(label, callback) {
  const preflight = await runProductionPreflight();
  if (preflight.status !== 0) {
    throw new ProductionRevisionError("COMMAND_FAILED", `${label}: SSH preflight failed.`);
  }
  const result = await callback();
  requireSuccess(result, `${label} failed.`);
  return result;
}

function prepareArchive(revision) {
  mkdirSync(tempRoot, { recursive: true });
  rmSync(archivePath, { force: true });
  const result = runCommand("git", ["archive", "--format=zip", `--output=${archivePath}`, revision], {
    cwd: repositoryRoot,
  });
  requireSuccess(result, "Source archive creation failed.");
}

function ensureRemoteLayout() {
  return runRemotePowerShell([
    "$ErrorActionPreference='Stop'",
    "$root='C:\\BielOS'",
    "New-Item -ItemType Directory -Force -Path $root,(Join-Path $root '.deploy-tmp') | Out-Null",
    "$marker=Join-Path $root '.bielos-production-host'",
    "if(Test-Path -LiteralPath $marker){$lines=Get-Content -LiteralPath $marker -Raw; if($lines -notmatch '(?m)^role=production$' -or $lines -notmatch '(?m)^path=C:\\\\BielOS$' -or $lines -notmatch ('(?m)^hostname=' + [regex]::Escape([Environment]::MachineName) + '$')){throw 'Production-host identity marker mismatch.'}} else {Set-Content -LiteralPath $marker -Value @('role=production','protocol=1',('hostname=' + [Environment]::MachineName),'path=C:\\BielOS') -Encoding ascii}",
    "Write-Output ('ENV_MISSING=' + (-not (Test-Path -LiteralPath (Join-Path $root '.env'))))",
  ].join(";"));
}

function installArchive(revision) {
  return runRemotePowerShell([
    "$ErrorActionPreference='Stop'",
    "$root='C:\\BielOS'",
    "$zip=Join-Path $root '.deploy-tmp\\production-source.zip'",
    "$stage=Join-Path $root '.deploy-tmp\\stage'",
    `$revision='${revision}'`,
    "if($revision -notmatch '^[0-9a-f]{40}$'){throw 'Invalid deployment revision.'}",
    "if(-not (Test-Path -LiteralPath $zip -PathType Leaf)){throw 'Source archive is missing.'}",
    "Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue",
    "Expand-Archive -LiteralPath $zip -DestinationPath $stage -Force",
    "if(-not (Test-Path -LiteralPath (Join-Path $stage 'scripts\\production-server.ps1'))){throw 'Source archive is incomplete.'}",
    "$reserved=@('.env','.bielos-production-host','.deploy-tmp','.bielos-deploy-revision','.bielos-source-state')",
    "Get-ChildItem -LiteralPath $root -Force | Where-Object {$reserved -notcontains $_.Name} | Remove-Item -Recurse -Force",
    "Get-ChildItem -LiteralPath $stage -Force | Move-Item -Destination $root -Force",
    "Set-Content -LiteralPath (Join-Path $root '.bielos-deploy-revision') -Value $revision -Encoding ascii",
    "Set-Content -LiteralPath (Join-Path $root '.bielos-source-state') -Value @('source=verified-archive','branch=main','clean=true',('revision=' + $revision)) -Encoding ascii",
    "Remove-Item -LiteralPath $stage,$zip -Recurse -Force",
    "Write-Output ('REMOTE_SOURCE_REVISION=' + $revision)",
  ].join(";"));
}

export async function deployProduction({ action = "restart" } = {}) {
  if (!["restart", "core-up"].includes(action)) {
    throw new ProductionRevisionError("ARGUMENT_INVALID");
  }

  const source = inspectProductionSource({ repositoryRoot });
  prepareArchive(source.revision);
  try {
    const layout = await guardedStage("remote layout", ensureRemoteLayout);
    if (layout.stdout.includes("ENV_MISSING=True")) {
      await guardedStage("private production environment transfer", () =>
        copyFileToRemote(path.join(repositoryRoot, ".env"), remoteEnvPath),
      );
    }
    await guardedStage("source transfer", () =>
      copyFileToRemote(archivePath, remoteArchivePath),
    );
    await guardedStage("source install", () => installArchive(source.revision));
    return runRemoteProductionCommand([action]);
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
}

if (process.argv[1] && process.argv[1].endsWith("deploy-production.mjs")) {
  deployProduction({ action: process.argv[2] ?? "restart" })
    .then((result) => {
      for (const line of result.lines ?? ["Remote deployment complete."]) console.log(line);
      process.exitCode = result.status ?? 0;
    })
    .catch((error) => {
      console.error(error instanceof ProductionRevisionError ? error.message : "Remote deployment failed.");
      process.exitCode = 1;
    });
}
