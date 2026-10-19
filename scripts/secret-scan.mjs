import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

const MAX_TEXT_FILE_BYTES = 1024 * 1024;
const MAX_GIT_BLOB_BYTES = 64 * 1024 * 1024;
const revisionArguments = process.argv.slice(2);
let revision = null;

if (revisionArguments.length > 0) {
  if (revisionArguments.length !== 2 || revisionArguments[0] !== "--revision" || !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/iu.test(revisionArguments[1])) {
    console.error("Secret scan failed: invalid arguments.");
    process.exit(2);
  }
  revision = revisionArguments[1];
}

const gitEnvironment = { ...process.env, GIT_NO_REPLACE_OBJECTS: "1" };
const sensitiveDirectorySegments = new Set(["backup", "backups", "dumps", "gmail", "takeout", "google takeout", "attachments", "secrets"]);

const forbiddenPathRules = [
  {
    id: "sensitive-export-directory",
    test: (filePath) => filePath !== "infra/backups/.gitkeep" && filePath.split("/").some((segment) => sensitiveDirectorySegments.has(segment))
  },
  {
    id: "env-file",
    test: (filePath) => {
      const name = path.posix.basename(filePath);
      return name !== ".env.example" && (name === ".env" || name.startsWith(".env."));
    }
  },
  {
    id: "cloudflare-credentials-json",
    test: (filePath) => filePath.startsWith("infra/cloudflare/") && filePath.endsWith(".json")
  },
  {
    id: "aws-credentials",
    test: (filePath) => /(?:^|\/)\.aws\/(?:credentials|config)$/u.test(filePath)
  },
  {
    id: "database-dump",
    test: (filePath) =>
      /\.(?:bak|backup|db|dump|sqlite|sqlite3|sql)(?:\.(?:gz|gzip|bz2|xz|zst|lz4)|-(?:wal|shm|journal))?$/u.test(filePath) &&
      !/^packages\/database\/prisma\/migrations\/[^/]+\/migration\.sql$/i.test(filePath)
  },
  {
    id: "application-log",
    test: (filePath) => /\.log(?:\.\d+)?(?:\.(?:gz|gzip|bz2|xz|zst|lz4))?$/u.test(filePath)
  },
  {
    id: "google-takeout-export",
    test: (filePath) => /(?:^|\/)(?:google[-_ ]?takeout|takeout)(?:\/|[-_.])/i.test(filePath)
  },
  {
    id: "gmail-export-or-attachment",
    test: (filePath) => /(?:^|\/)(?:gmail|mail-attachments?|attachments?)\//i.test(filePath)
  },
  {
    id: "private-key-file",
    test: (filePath) => /(?:^|\/)(?:id_(?:rsa|dsa|ecdsa|ed25519)(?:\.(?:gz|gzip|bz2|xz|zst|lz4))*|.*\.(?:pem|key|p12|pfx|der|jks|keystore)(?:\.(?:gz|gzip|bz2|xz|zst|lz4))*)$/iu.test(filePath)
  }
];

const contentRules = [
  {
    id: "private-key-block",
    pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/
  },
  {
    id: "jwt",
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/
  },
  {
    id: "aws-access-key",
    pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/
  },
  {
    id: "google-api-key",
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/
  },
  {
    id: "github-token",
    pattern: /\bgh[pousr]_[A-Za-z0-9_]{36,}\b/
  },
  {
    id: "slack-token",
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/
  },
  {
    id: "stripe-secret-key",
    pattern: /\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b/
  },
  {
    id: "cloudflare-token-assignment",
    pattern:
      /\b(?:CLOUDFLARE_TUNNEL_TOKEN|TUNNEL_TOKEN|CF_API_TOKEN|CLOUDFLARE_API_TOKEN)\b\s*[:=]\s*["']?(?!$|<|replace|placeholder)[A-Za-z0-9._-]{20,}/i
  },
  {
    id: "generic-secret-assignment",
    pattern:
      /\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|secret|token)\b["']?\s*[:=]\s*["']?(?!$|<|false|local-validation-only|owner@example\.invalid|placeholder|replace)[A-Za-z0-9_./+=-]{24,}/i
  }
];

const applicationKeyPattern = /\b(?:[a-z][a-z0-9]*[_-])*(?:(?:api|signing|encryption|private)[_-]?key|secret)\b["']?\s*[:=]\s*(["']?)([A-Za-z0-9_./+=-]{24,})/gi;
const databaseUrlPattern =
  /\b(?:(?:postgres(?:ql)?)|mysql|mongodb(?:\+srv)?):\/\/([^:\s/]+):([^@\s]+)@/gi;
const allowedPlaceholderValues = new Set([
  "local-validation-only",
  "synthetic-private-key-material",
  "placeholder",
  "replace",
  "replace-with-local-secret",
  "change-me-in-your-local-env"
]);

const findings = [];

for (const { filePath, objectId } of revision ? getRevisionFiles(revision) : getRepositoryFiles()) {
  scanFilePath(filePath);
  scanFileContents(filePath, objectId);
}

if (findings.length > 0) {
  console.error("Secret scan failed. Potential secret material was found:");

  for (const finding of findings) {
    console.error(`- ${finding.file}:${finding.line ?? 1} ${finding.rule}`);
  }

  console.error("No secret values were printed. Remove the file/value or replace it with a safe placeholder.");
  process.exit(1);
}

console.log("Secret scan passed.");

function getRepositoryFiles() {
  const output = execFileSync("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], {
    encoding: "buffer"
  });

  return output
    .toString("utf8")
    .split("\0")
    .filter(Boolean)
    .map((filePath) => ({ filePath: filePath.replaceAll("\\", "/"), objectId: null }));
}

function getRevisionFiles(sourceRevision) {
  const output = execFileSync("git", ["ls-tree", "-r", "-z", "--full-tree", sourceRevision], {
    encoding: "buffer",
    env: gitEnvironment
  });

  return output
    .toString("utf8")
    .split("\0")
    .filter(Boolean)
    .map((record) => {
      const separator = record.indexOf("\t");
      if (separator < 0) throw new Error("Invalid Git tree entry.");
      const [mode, type, objectId] = record.slice(0, separator).split(" ");
      if (type !== "blob" || !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/iu.test(objectId ?? "")) return null;
      if (mode !== "100644" && mode !== "100755" && mode !== "120000") return null;
      return { filePath: record.slice(separator + 1).replaceAll("\\", "/"), objectId };
    })
    .filter((entry) => entry !== null);
}

function scanFilePath(filePath) {
  const normalizedPath = filePath.replaceAll("\\", "/").toLowerCase();
  for (const rule of forbiddenPathRules) {
    if (rule.test(normalizedPath)) {
      findings.push({
        file: filePath,
        rule: rule.id
      });
    }
  }
}

function scanFileContents(filePath, objectId) {
  let buffer;

  try {
    if (objectId) {
      buffer = execFileSync("git", ["cat-file", "blob", objectId], {
        encoding: "buffer",
        env: gitEnvironment,
        maxBuffer: MAX_GIT_BLOB_BYTES
      });
    } else {
      if (!existsSync(filePath)) return;
      buffer = readFileSync(filePath);
    }
  } catch {
    findings.push({
      file: filePath,
      rule: "unreadable-tracked-file"
    });
    return;
  }

  if (buffer.includes(0)) {
    let binaryText = buffer.toString("latin1");
    // NUL-delimited ASCII runs preserve UTF-16LE/BE text for the ordinary secret patterns.
    // eslint-disable-next-line no-control-regex -- binary NUL bytes must be collapsed before content scanning.
    binaryText = binaryText.replace(/([\x20-\x7e])\x00|\x00(?=[\x20-\x7e])/gu, "$1");
    // eslint-disable-next-line no-control-regex -- remaining binary control bytes separate unrelated text runs.
    binaryText = binaryText.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/gu, "\n");
    scanLine(filePath, 1, binaryText);
    return;
  }
  if (buffer.length > MAX_TEXT_FILE_BYTES) {
    findings.push({
      file: filePath,
      rule: "oversized-text-file"
    });
    return;
  }

  const text = buffer.toString("utf8");
  const lines = text.split(/\r?\n/);

  for (const [index, line] of lines.entries()) {
    scanLine(filePath, index + 1, line);
  }
}

function scanLine(filePath, lineNumber, line) {
  for (const rule of contentRules) {
    if (rule.pattern.test(line)) {
      findings.push({
        file: filePath,
        line: lineNumber,
        rule: rule.id
      });
    }
  }

  for (const match of line.matchAll(applicationKeyPattern)) {
    // Source identifiers and environment references are code; only literals are credential assignments there.
    if (/\.(?:[cm]?[jt]sx?)$/iu.test(filePath) && !match[1]) continue;
    if (isAllowedPlaceholder(match[2])) continue;
    findings.push({ file: filePath, line: lineNumber, rule: "application-key-assignment" });
  }

  const databaseUrlMatches = [...line.matchAll(databaseUrlPattern)];

  if (databaseUrlMatches.some((match) => !isAllowedPlaceholder(match[2]))) {
    findings.push({
      file: filePath,
      line: lineNumber,
      rule: "database-url-with-password"
    });
  }
}

function isAllowedPlaceholder(value) {
  const normalized = value.trim().toLowerCase();
  return allowedPlaceholderValues.has(normalized) || normalized.startsWith("replace-") || /^\$(?:[a-z_][a-z\d_]*|\{[a-z_][a-z\d_]*\})$/iu.test(value.trim());
}
