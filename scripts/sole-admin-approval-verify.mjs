#!/usr/bin/env node
import { readFileSync, lstatSync } from "node:fs";
import { resolve } from "node:path";
import { verifySoleAdminApprovalBundle } from "./lib/sole-admin-approval.mjs";

const usage = "Usage: node scripts/sole-admin-approval-verify.mjs --bundle <file> --registry <file> --registry-sha256 <64-lowercase-hex> --expected <file>";
const KEYS = ["--bundle", "--registry", "--registry-sha256", "--expected"];

function readBoundedJson(name) {
  const path = resolve(name);
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.size < 2 || stat.size > 16 * 1024) throw new Error("Invalid evidence file.");
  return readFileSync(path);
}

function readCanonicalJson(name) {
  const bytes = readBoundedJson(name);
  const json = bytes.toString("utf8");
  if (!bytes.equals(Buffer.from(json, "utf8"))) throw new Error("Invalid evidence encoding.");
  const parsed = JSON.parse(json);
  // Fail closed on duplicate-key ambiguity, padding, BOM and human/parser
  // disagreements. The offline evidence format uses compact canonical JSON.
  if (JSON.stringify(parsed) !== json) throw new Error("Ambiguous evidence JSON.");
  return parsed;
}

function main(args) {
  if (args.length !== 8) throw new Error("Invalid arguments.");
  const options = new Map();
  for (let i = 0; i < args.length; i += 2) {
    if (!KEYS.includes(args[i]) || options.has(args[i]) || !args[i + 1]) throw new Error("Invalid arguments.");
    options.set(args[i], args[i + 1]);
  }
  if (options.size !== KEYS.length) throw new Error("Invalid arguments.");
  const bundle = readCanonicalJson(options.get("--bundle"));
  const expected = readCanonicalJson(options.get("--expected"));
  const result = verifySoleAdminApprovalBundle({
    bundle,
    registryBytes: readBoundedJson(options.get("--registry")),
    expectedRegistrySha256: options.get("--registry-sha256"),
    expected
  });
  // A signature proof is not identity verification or permission to reset.
  process.stdout.write(`REVIEW_SIGNATURES_VALID request_sha256=${result.requestSha256}\nNO_CREDENTIAL_MUTATION_AUTHORIZED\n`);
}

try {
  if (process.argv.length === 3 && process.argv[2] === "--help") {
    process.stdout.write(`${usage}\n`);
  } else {
    main(process.argv.slice(2));
  }
} catch {
  // Never echo file paths, supplied identifiers, the manifest, or key material.
  process.stderr.write(`REVIEW_SIGNATURES_REJECTED\n${usage}\n`);
  process.exitCode = 1;
}
