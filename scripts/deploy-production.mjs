import { existsSync, mkdirSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  inspectProductionSource,
  ProductionRevisionError,
  runCommand,
} from "./lib/production-revision.mjs";
import { PRODUCTION_CONFIG, isValidProductionConfig } from "./lib/production-config.mjs";
import { SSH_OPTIONS, runProductionPreflight } from "./production-preflight.mjs";
import { runRemoteProductionCommand } from "./production-remote.mjs";

const repositoryRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const tempRoot = path.join(repositoryRoot, ".bielos-mission-tmp", "deploy");
const archivePath = path.join(tempRoot, "production-source.zip");

function encodePowerShell(script) {
  return Buffer.from(script, "utf16le").toString("base64");
}

function remotePath(root, suffix) {
  return `${root.replaceAll("\\", "/")}/${suffix.replaceAll("\\", "/")}`;
}

function runRemotePowerShell(script, config) {
  return runCommand("ssh", [
    ...SSH_OPTIONS,
    config.sshAlias,
    "powershell.exe",
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-EncodedCommand",
    encodePowerShell(script),
  ]);
}

function copyFileToRemote(localPath, target, config) {
  return runCommand("scp", [
    ...SSH_OPTIONS,
    localPath,
    `${config.sshAlias}:${target}`,
  ]);
}

function requireSuccess(result, message) {
  if (result.status !== 0) throw new ProductionRevisionError("COMMAND_FAILED", message);
}

async function guardedStage(label, callback, config) {
  const preflight = await runProductionPreflight({ config });
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

function ensureRemoteLayout(config) {
  const root = config.root;
  const script = [
    "$ErrorActionPreference='Stop'",
    `$root='${root}'`,
    "New-Item -ItemType Directory -Force -Path $root,(Join-Path $root '.deploy-tmp'),(Join-Path $root 'backups') | Out-Null",
    "$marker=Join-Path $root '.bielos-production-host'",
    `if(Test-Path -LiteralPath $marker){$lines=@(Get-Content -LiteralPath $marker); if($lines -notcontains 'role=production' -or $lines -notcontains 'protocol=1' -or $lines -notcontains ('path=' + $root) -or $lines -notcontains ('hostname=' + [Environment]::MachineName)){throw 'Production-host identity marker mismatch.'}} else {Set-Content -LiteralPath $marker -Value @('role=production','protocol=1',('hostname=' + [Environment]::MachineName),('path=' + $root)) -Encoding ascii}`,
    "Write-Output ('ENV_MISSING=' + (-not (Test-Path -LiteralPath (Join-Path $root '.env'))))",
    "Write-Output ('OIDC_ENV_MISSING=' + (-not (Test-Path -LiteralPath (Join-Path $root '.env.oidc'))))",
  ].join(";");
  return runRemotePowerShell(script, config);
}

function createPrivateOidcEnvironment(config) {
  return runRemotePowerShell(buildPrivateOidcEnvironmentScript(config.root), config);
}

export function buildPrivateOidcEnvironmentScript(root) {
  return [
    "$ErrorActionPreference='Stop'",
    `$root='${root}'`,
    "$oidcPath=Join-Path $root '.env.oidc'",
    "if(-not (Test-Path -LiteralPath $oidcPath)){",
    "$rng=[Security.Cryptography.RandomNumberGenerator]::Create()",
    "$cookieBytes=New-Object byte[] 32; $rng.GetBytes($cookieBytes)",
    "$adapterBytes=New-Object byte[] 32; $rng.GetBytes($adapterBytes)",
    "$ecdsa=[Security.Cryptography.ECDsaCng]::new(256)",
    "$parameters=$ecdsa.ExportParameters($true)",
    "$toUrlBase64={param([byte[]]$value) [Convert]::ToBase64String($value).TrimEnd('=').Replace('+','-').Replace('/','_')}",
    "$publicX=& $toUrlBase64 $parameters.Q.X; $publicY=& $toUrlBase64 $parameters.Q.Y; $privateD=& $toUrlBase64 $parameters.D",
    "$jwkKey=@{kty='EC';crv='P-256';alg='ES256';use='sig';kid=[guid]::NewGuid().ToString('N');x=$publicX;y=$publicY;d=$privateD}",
    "$jwk=ConvertTo-Json -InputObject @{keys=@($jwkKey)} -Compress -Depth 4",
    "$cookie=&$toUrlBase64 $cookieBytes",
    "$adapter=[BitConverter]::ToString($adapterBytes).Replace('-','').ToLowerInvariant()",
    "$lines=@('BIELOS_OIDC_ISSUER=https://portal.biel.dev.br',('BIELOS_OIDC_SIGNING_JWKS=' + $jwk),('BIELOS_OIDC_COOKIE_KEY=' + $cookie),('BIELOS_OIDC_ADAPTER_KEY=' + $adapter))",
    "[IO.File]::WriteAllLines($oidcPath,$lines,[Text.UTF8Encoding]::new($false))",
    "$ecdsa.Dispose(); $rng.Dispose()",
    "}",
    "if(-not (Test-Path -LiteralPath $oidcPath -PathType Leaf)){throw 'OIDC private environment file is invalid.'}",
    "$current=[Security.Principal.WindowsIdentity]::GetCurrent().User",
    "$acl=New-Object Security.AccessControl.FileSecurity; $acl.SetOwner($current); $acl.SetAccessRuleProtection($true,$false)",
    "foreach($sidText in @($current.Value,'S-1-5-18','S-1-5-32-544')){$sid=[Security.Principal.SecurityIdentifier]::new($sidText); $rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.AccessControlType]::Allow); $acl.AddAccessRule($rule)}",
    "[IO.File]::SetAccessControl($oidcPath,$acl)",
    "Write-Output 'OIDC_ENV_READY=true'",
  ].join(";");
}

function installArchive(revision, config) {
  const root = config.root;
  return runRemotePowerShell([
    "$ErrorActionPreference='Stop'",
    `$root='${root}'`,
    "$zip=Join-Path $root '.deploy-tmp\\production-source.zip'",
    "$stage=Join-Path $root '.deploy-tmp\\stage'",
    `$revision='${revision}'`,
    "if($revision -notmatch '^[0-9a-f]{40}$'){throw 'Invalid deployment revision.'}",
    "if(-not (Test-Path -LiteralPath $zip -PathType Leaf)){throw 'Source archive is missing.'}",
    "Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue",
    "Expand-Archive -LiteralPath $zip -DestinationPath $stage -Force",
    "if(-not (Test-Path -LiteralPath (Join-Path $stage 'scripts\\production-server.ps1'))){throw 'Source archive is incomplete.'}",
    "$reserved=@('.env','.env.oidc','.bielos-production-host','.deploy-tmp','backups','.bielos-deploy-revision','.bielos-source-state','.bielos-migration-verification')",
    "Get-ChildItem -LiteralPath $root -Force | Where-Object {$reserved -notcontains $_.Name} | Remove-Item -Recurse -Force",
    "Get-ChildItem -LiteralPath $stage -Force | Move-Item -Destination $root -Force",
    "Set-Content -LiteralPath (Join-Path $root '.bielos-deploy-revision') -Value $revision -Encoding ascii",
    "Set-Content -LiteralPath (Join-Path $root '.bielos-source-state') -Value @('source=verified-archive','branch=main','clean=true',('revision=' + $revision)) -Encoding ascii",
    "Remove-Item -LiteralPath $stage,$zip -Recurse -Force",
    "Write-Output ('REMOTE_SOURCE_REVISION=' + $revision)",
  ].join(";"), config);
}

function migrationPlan() {
  const directory = path.join(repositoryRoot, "packages", "database", "prisma", "migrations");
  const hasTransition = existsSync(path.join(directory, "20260922090000_total_identity_security_rebaseline", "migration.sql"));
  const hasBaseline = existsSync(path.join(directory, "0_init", "migration.sql"));
  if (hasTransition && hasBaseline) throw new ProductionRevisionError("MIGRATION_PLAN_AMBIGUOUS");
  if (hasTransition) return "transition";
  if (hasBaseline) return "baseline";
  throw new ProductionRevisionError("MIGRATION_PLAN_MISSING");
}

async function runRemoteAction(action, config) {
  const result = await runRemoteProductionCommand([action], { config });
  if (result.status !== 0) {
    throw new ProductionRevisionError("COMMAND_FAILED", `${action} failed.`);
  }
  return result;
}

export async function deployProduction({ action = "rebaseline", config = PRODUCTION_CONFIG } = {}) {
  if (!isValidProductionConfig(config)) throw new ProductionRevisionError("OPERATOR_CONFIG_INVALID");
  if (!["install", "restart", "rebaseline"].includes(action)) {
    throw new ProductionRevisionError("ARGUMENT_INVALID");
  }

  const source = inspectProductionSource({ repositoryRoot });
  const plan = migrationPlan();
  prepareArchive(source.revision);
  try {
    const layout = await guardedStage("remote layout", () => ensureRemoteLayout(config), config);
    if (layout.stdout.includes("ENV_MISSING=True")) {
      await guardedStage("private production environment transfer", () => {
        const localEnv = path.join(repositoryRoot, ".env");
        if (!existsSync(localEnv)) throw new ProductionRevisionError("PRIVATE_ENV_MISSING");
        return copyFileToRemote(localEnv, remotePath(config.root, ".env"), config);
      }, config);
    }
    await guardedStage("OIDC signing environment setup", () => createPrivateOidcEnvironment(config), config);
    await guardedStage("source transfer", () => copyFileToRemote(archivePath, remotePath(config.root, ".deploy-tmp/production-source.zip"), config), config);
    await guardedStage("source install", () => installArchive(source.revision, config), config);
    if (action === "install") {
      return { status: 0, lines: ["Remote source staged; migration and services were not changed."] };
    }

    await runRemoteAction("prepare", config);
    await runRemoteAction("backup-verify", config);
    await runRemoteAction(plan === "transition" ? "migrate" : "baseline", config);
    const deployed = await runRemoteAction("restart", config);
    const status = await runRemoteAction("migration-status", config);
    return {
      status: 0,
      lines: [
        `Production ${plan} completed for source ${source.revision}.`,
        ...deployed.lines,
        ...status.lines,
      ],
    };
  } finally {
    const relativeTemp = path.relative(repositoryRoot, tempRoot);
    if (!relativeTemp.startsWith("..") && !path.isAbsolute(relativeTemp)) {
      rmSync(tempRoot, { recursive: true, force: true });
    }
  }
}

if (process.argv[1] && process.argv[1].endsWith("deploy-production.mjs")) {
  deployProduction({ action: process.argv[2] ?? "rebaseline" })
    .then((result) => {
      for (const line of result.lines ?? ["Remote deployment complete."]) console.log(line);
      process.exitCode = result.status ?? 0;
    })
    .catch((error) => {
      console.error(error instanceof ProductionRevisionError ? error.message : "Remote deployment failed.");
      process.exitCode = 1;
    });
}
