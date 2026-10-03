import { createHash, randomBytes } from "node:crypto";
import { createReadStream, lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  CANONICAL_BIELOS_REPOSITORY,
  inspectProductionSource,
  ProductionRevisionError,
  runCommand,
} from "./lib/production-revision.mjs";
import { verifyExactShaCi } from "./lib/production-ci.mjs";
import { SSH_OPTIONS, runProductionPreflight } from "./production-preflight.mjs";
import { readProductionConfig, isValidProductionConfig } from "./lib/production-config.mjs";

const repositoryRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const serverScriptPath = "scripts/production-server.sh";
const secretScannerRelativePath = "scripts/secret-scan.mjs";
const backupDirectorySentinel = "infra/backups/.gitkeep";
const reservedArchiveSegments = new Set([
  ".env",
  ".production.operator.json",
  ".bielos-release",
  ".bielos-production-host",
  ".npmrc",
  ".dev.vars",
  "backups",
  "backup",
  "dumps",
  "releases",
  "current",
  "google takeout",
  "takeout",
  "gmail",
  "attachments",
  "secrets",
]);

function isSensitiveArchivePath(entry) {
  const normalizedEntry = entry.replaceAll("\\", "/").toLowerCase().replace(/\/+$/u, "");
  if (normalizedEntry === "infra/backups" || normalizedEntry === backupDirectorySentinel) return false;
  const segments = entry.split("/");
  const normalizedSegments = segments.map((segment) => segment.toLowerCase());
  const name = segments.at(-1) ?? "";
  if (normalizedSegments.some((segment) => reservedArchiveSegments.has(segment) || segment.startsWith(".dev.vars.") ||
    (segment.startsWith(".env.") && segment !== ".env.example") || /^mail-attachments?$/u.test(segment) || /^takeout(?:[-_.]|$)/u.test(segment))) {
    return true;
  }
  if (normalizedSegments[0] === "infra" && normalizedSegments[1] === "cloudflare" && name.toLowerCase().endsWith(".json")) return true;
  if (/^(?:\.aws\/(?:credentials|config)|secrets\/[^/]+\.(?:pem|key))$/iu.test(entry) ||
    /(?:^|\/)id_(?:rsa|dsa|ecdsa|ed25519)(?:\.(?:gz|gzip|bz2|xz|zst|lz4))*$/iu.test(entry)) return true;
  if (/\.(?:pem|key|p12|pfx|der|jks|keystore|zip|tar|tgz|tar\.gz|tar\.[a-z0-9]+|mbox|log(?:\.[^/]+)*)(?:\.(?:gz|gzip|bz2|xz|zst|lz4))*$/iu.test(name)) return true;
  if (/\.(?:sqlite3?|db|dump|bak|backup|sql)(?:\.(?:gz|gzip|bz2|xz|zst|lz4)|-(?:wal|shm|journal))?$/iu.test(name) &&
    !/^packages\/database\/prisma\/migrations\/[^/]+\/migration\.sql$/iu.test(entry)) return true;
  return false;
}

function requireSuccess(result, message) {
  if (!result || result.status !== 0) throw new ProductionRevisionError("COMMAND_FAILED", message);
  return result.stdout ?? "";
}

function sourceScript(revision, execute) {
  return requireSuccess(
    execute("git", ["show", `${revision}:${serverScriptPath}`], {
      cwd: repositoryRoot,
      env: { ...process.env, GIT_NO_REPLACE_OBJECTS: "1" },
    }),
    "Accepted production script could not be loaded from the verified source revision.",
  );
}

function makeArchive(revision, execute) {
  const directory = mkdtempSync(path.join(os.tmpdir(), "bielos-production-"));
  try {
    const archivePath = path.join(directory, "source.tar");
    const gitEnvironment = { ...process.env, GIT_NO_REPLACE_OBJECTS: "1" };
    const archive = execute("git", ["archive", "--format=tar", `--output=${archivePath}`, revision], {
      cwd: repositoryRoot,
      env: gitEnvironment,
    });
    requireSuccess(archive, "Accepted production source archive could not be created.");

    const treeListing = requireSuccess(
      execute("git", ["ls-tree", "-r", "-t", "-z", "--full-tree", revision], {
        cwd: repositoryRoot,
        env: gitEnvironment,
      }),
      "Accepted production source tree could not be inspected.",
    );
    const sourcePaths = [];
    for (const record of treeListing.split("\0").filter(Boolean)) {
      const separator = record.indexOf("\t");
      if (separator < 0) throw new ProductionRevisionError("COMMAND_FAILED");
      const [mode, type, objectId] = record.slice(0, separator).split(" ");
      const entry = record.slice(separator + 1);
      if (mode !== "040000" && mode !== "100644" && mode !== "100755") {
        throw new ProductionRevisionError("COMMAND_FAILED");
      }
      sourcePaths.push(entry);
      if (entry.replaceAll("\\", "/").toLowerCase() === backupDirectorySentinel) {
        if (mode !== "100644" || type !== "blob" || !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/iu.test(objectId ?? "")) {
          throw new ProductionRevisionError("COMMAND_FAILED");
        }
        const sentinelSize = requireSuccess(
          execute("git", ["cat-file", "-s", objectId], { cwd: repositoryRoot, env: gitEnvironment }),
          "Production backup sentinel could not be inspected.",
        );
        if (sentinelSize.trim() !== "0") throw new ProductionRevisionError("COMMAND_FAILED");
      }
      if (isSensitiveArchivePath(entry)) {
        throw new ProductionRevisionError("COMMAND_FAILED");
      }
    }

    const attributes = requireSuccess(
      execute("git", ["check-attr", "--cached", "-z", "export-ignore", "export-subst", "--stdin"], {
        cwd: repositoryRoot,
        env: gitEnvironment,
        input: sourcePaths.join("\0") + "\0",
      }),
      "Accepted production source attributes could not be inspected.",
    );
    const attributeFields = attributes.split("\0").filter(Boolean);
    if (attributeFields.length !== sourcePaths.length * 6) throw new ProductionRevisionError("COMMAND_FAILED");
    for (let index = 0; index < attributeFields.length; index += 3) {
      const attribute = attributeFields[index + 1];
      const value = attributeFields[index + 2];
      if (!["export-ignore", "export-subst"].includes(attribute) || !["unspecified", "unset", "false"].includes(value)) {
        throw new ProductionRevisionError("COMMAND_FAILED");
      }
    }

    const listing = requireSuccess(execute("tar", ["-tf", archivePath]), "Production source archive could not be inspected.");
    const paths = listing.split(/\r?\n/u).filter(Boolean);
    if (paths.some(isSensitiveArchivePath)) {
      throw new ProductionRevisionError("COMMAND_FAILED");
    }

    const scannerSource = requireSuccess(
      execute("git", ["show", `${revision}:${secretScannerRelativePath}`], {
        cwd: repositoryRoot,
        env: gitEnvironment,
      }),
      "Accepted production secret scanner could not be loaded.",
    );
    const scannerPath = path.join(directory, "secret-scan.mjs");
    writeFileSync(scannerPath, scannerSource, { encoding: "utf8", flag: "wx", mode: 0o600 });
    requireSuccess(
      execute(process.execPath, [scannerPath, "--revision", revision], {
        cwd: repositoryRoot,
        env: gitEnvironment,
      }),
      "Accepted production source failed the secret scan.",
    );

    return {
      archivePath,
      directory,
      archiveHash: createHash("sha256").update(readFileSync(archivePath)).digest("hex"),
    };
  } catch (error) {
    rmSync(directory, { recursive: true, force: true });
    throw error;
  }
}

function copyArchive(archivePath, revision, archiveId, config, execute) {
  const remotePath = `${config.root}/.deploy-tmp/source-${revision}-${archiveId}.tar`;
  return execute("scp", [
    ...SSH_OPTIONS,
    archivePath,
    `${config.sshAlias}:${remotePath}`,
  ]);
}

function copyImageArchive(archivePath, revision, archiveId, config, execute) {
  const remotePath = `${config.root}/.deploy-tmp/images-${revision}-${archiveId}.tar.gz`;
  return execute("scp", [
    ...SSH_OPTIONS,
    archivePath,
    `${config.sshAlias}:${remotePath}`,
  ]);
}

async function hashFile(filePath) {
  const hash = createHash("sha256");
  await new Promise((resolve, reject) => {
    const stream = createReadStream(filePath);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("error", reject);
    stream.on("end", resolve);
  });
  return hash.digest("hex");
}

async function downloadProductionImages({ runId, revision, platform, execute }) {
  if (!Number.isSafeInteger(runId) || runId <= 0 || !["linux/amd64", "linux/arm64"].includes(platform)) {
    throw new ProductionRevisionError("COMMAND_FAILED");
  }
  const directory = mkdtempSync(path.join(os.tmpdir(), "bielos-production-images-"));
  try {
    const platformName = platform.replace("/", "-");
    const artifactName = `bielos-production-images-${revision}-${platformName}`;
    requireSuccess(
      execute("gh", [
        "run", "download", String(runId),
        "--repo", CANONICAL_BIELOS_REPOSITORY,
        "--name", artifactName,
        "--dir", directory,
      ], { cwd: repositoryRoot }),
      "Exact-revision production images could not be downloaded from CI.",
    );
    const archiveName = "bielos-production-images.tar.gz";
    const entries = readdirSync(directory);
    const archivePath = path.join(directory, archiveName);
    if (entries.length !== 1 || entries[0] !== archiveName || !lstatSync(archivePath).isFile()) {
      throw new ProductionRevisionError("COMMAND_FAILED");
    }
    return {
      archivePath,
      directory,
      archiveHash: await hashFile(archivePath),
    };
  } catch (error) {
    rmSync(directory, { recursive: true, force: true });
    throw error;
  }
}

function runRemoteScript(action, revision, archiveHash, archiveId, imageHash, imageId, script, config, execute) {
  if (!isValidProductionConfig(config)) throw new ProductionRevisionError("OPERATOR_CONFIG_INVALID");
  const archiveArguments = archiveHash ? ` ${archiveHash} ${archiveId}` : "";
  const imageArguments = imageHash ? ` ${imageHash} ${imageId}` : "";
  const remoteCommand = `bash -s -- ${action} ${config.root} ${revision}${archiveArguments}${imageArguments}`;
  return execute("ssh", [...SSH_OPTIONS, config.sshAlias, remoteCommand], { input: script });
}

function cleanupRemoteStaging(revision, archiveId, script, config, execute) {
  if (!isValidProductionConfig(config) || !/^[0-9a-f]{40}$/u.test(revision) || !/^[a-f0-9]{24}$/u.test(archiveId)) {
    throw new ProductionRevisionError("COMMAND_FAILED", "Failed production artifact transfer could not be safely identified for cleanup.");
  }
  const remoteCommand = `bash -s -- cleanup-deploy-staging ${config.root} ${revision} ${archiveId}`;
  return execute("ssh", [...SSH_OPTIONS, config.sshAlias, remoteCommand], { input: script });
}

function cleanupAfterFailure(error, revision, archiveId, script, config, execute) {
  let cleanupResult;
  let cleanupFailed = false;
  try {
    cleanupResult = cleanupRemoteStaging(revision, archiveId, script, config, execute);
  } catch {
    cleanupFailed = true;
  }
  if (cleanupFailed || cleanupResult?.status !== 0) {
    throw new ProductionRevisionError("COMMAND_FAILED", "Production operation failed and remote staging cleanup could not be confirmed.");
  }
  throw error;
}

export async function deployProduction({
  action = "deploy",
  config = readProductionConfig(),
  execute = runCommand,
  inspectSource = inspectProductionSource,
  verifyCi = verifyExactShaCi,
  preflight = runProductionPreflight,
} = {}) {
  if (!isValidProductionConfig(config)) throw new ProductionRevisionError("OPERATOR_CONFIG_INVALID");
  if (!["install", "deploy"].includes(action)) throw new ProductionRevisionError("ARGUMENT_INVALID");

  const source = inspectSource({ repositoryRoot, execute });
  const ci = verifyCi({ revision: source.revision, execute, repositoryRoot });
  if (!ci.ok) return { status: 1, lines: ci.lines };

  let archive;
  let imageArchive;
  const archiveId = randomBytes(12).toString("hex");
  try {
    archive = makeArchive(source.revision, execute);
    const sourceCode = sourceScript(source.revision, execute);
    const preflightResult = await preflight({ execute, config });
    if (preflightResult.status !== 0) return preflightResult;

    if (action === "deploy") {
      imageArchive = await downloadProductionImages({
        runId: ci.runId,
        revision: source.revision,
        platform: preflightResult.platform,
        execute,
      });
    }
    try {
      requireSuccess(copyArchive(archive.archivePath, source.revision, archiveId, config, execute), "Verified source archive transfer failed.");
      if (imageArchive) {
        requireSuccess(copyImageArchive(imageArchive.archivePath, source.revision, archiveId, config, execute), "Exact-revision production image transfer failed.");
      }
    } catch (error) {
      cleanupAfterFailure(error, source.revision, archiveId, sourceCode, config, execute);
    }

    if (action === "install") {
      const installed = requireSuccess(
        runRemoteScript("install-source", source.revision, archive.archiveHash, archiveId, "", "", sourceCode, config, execute),
        "Remote source staging failed.",
      );
      return { status: 0, lines: [...preflightResult.lines, ...installed.trim().split(/\r?\n/u).filter(Boolean), "Source staged; migration and services were not changed."] };
    }

    let deployed;
    try {
      deployed = requireSuccess(
        runRemoteScript("deploy", source.revision, archive.archiveHash, archiveId, imageArchive.archiveHash, archiveId, sourceCode, config, execute),
        "Remote deployment stopped. Maintenance remains active if production mutation had begun.",
      );
    } catch (error) {
      cleanupAfterFailure(error, source.revision, archiveId, sourceCode, config, execute);
    }
    return {
      status: 0,
      lines: [
        ...preflightResult.lines,
        ...deployed.trim().split(/\r?\n/u).filter(Boolean),
      ],
    };
  } finally {
    if (archive?.directory && path.dirname(archive.directory) === os.tmpdir()) {
      rmSync(archive.directory, { recursive: true, force: true });
    }
    if (imageArchive?.directory && path.dirname(imageArchive.directory) === os.tmpdir()) {
      rmSync(imageArchive.directory, { recursive: true, force: true });
    }
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  deployProduction({ action: process.argv[2] ?? "deploy" })
    .then((result) => {
      for (const line of result.lines ?? ["Remote deployment complete."]) console.log(line);
      process.exitCode = result.status ?? 0;
    })
    .catch((error) => {
      console.error(error instanceof ProductionRevisionError ? error.message : "Remote deployment failed.");
      process.exitCode = 1;
    });
}
