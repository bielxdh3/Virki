import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";

const MAX_TEXT_FILE_BYTES = 1024 * 1024;

const forbiddenPathRules = [
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
    id: "database-dump",
    test: (filePath) =>
      /\.(?:bak|backup|db|dump|sqlite|sqlite3|sql)$/i.test(filePath) &&
      !/^packages\/database\/prisma\/migrations\/[^/]+\/migration\.sql$/i.test(filePath)
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
    test: (filePath) => /(?:^|\/)(?:id_rsa|id_dsa|id_ecdsa|id_ed25519|.*\.pem|.*\.key)$/i.test(filePath)
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
      /\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|secret|token)\b\s*[:=]\s*["']?(?!$|<|false|local-validation-only|owner@example\.invalid|placeholder|replace)[A-Za-z0-9_./+=-]{24,}/i
  }
];

const databaseUrlPattern =
  /\b(?:(?:postgres(?:ql)?)|mysql|mongodb(?:\+srv)?):\/\/([^:\s/]+):([^@\s]+)@/i;
const allowedPlaceholderValues = new Set([
  "local-validation-only",
  "placeholder",
  "replace",
  "replace-with-local-secret",
  "change-me-in-your-local-env"
]);

const findings = [];

for (const filePath of getRepositoryFiles()) {
  scanFilePath(filePath);
  scanFileContents(filePath);
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
    .map((filePath) => filePath.replaceAll("\\", "/"));
}

function scanFilePath(filePath) {
  for (const rule of forbiddenPathRules) {
    if (rule.test(filePath)) {
      findings.push({
        file: filePath,
        rule: rule.id
      });
    }
  }
}

function scanFileContents(filePath) {
  let buffer;

  try {
    buffer = readFileSync(filePath);
  } catch {
    findings.push({
      file: filePath,
      rule: "unreadable-tracked-file"
    });
    return;
  }

  if (buffer.length > MAX_TEXT_FILE_BYTES || buffer.includes(0)) {
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

  const databaseUrlMatch = line.match(databaseUrlPattern);

  if (databaseUrlMatch && !isAllowedPlaceholder(databaseUrlMatch[2])) {
    findings.push({
      file: filePath,
      line: lineNumber,
      rule: "database-url-with-password"
    });
  }
}

function isAllowedPlaceholder(value) {
  const normalized = value.trim().toLowerCase();
  return allowedPlaceholderValues.has(normalized) || normalized.startsWith("replace-");
}
