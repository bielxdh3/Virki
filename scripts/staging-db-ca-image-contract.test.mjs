import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { rootCertificates } from "node:tls";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const productionDockerfile = readFileSync(path.join(root, "infra", "Dockerfile.prod"), "utf8").replace(/\r\n/gu, "\n");
const dockerfile = readFileSync(path.join(root, "infra", "Dockerfile.staging-db-trust"), "utf8").replace(/\r\n/gu, "\n");
const approvedBase = "ghcr.io/bielxdh3/virki-runtime@sha256:" + "a".repeat(64);
const secretName = "virki_staging_db_root_ca";
const imageCa = "/app/ca/staging-db-root.pem";
const imageCaDirectory = "/app/ca";
const imageSecret = `/run/secrets/${secretName}`;
const digest = bytes => createHash("sha256").update(bytes).digest("hex");

function assertImageContract(source) {
  assert.match(productionDockerfile, /^FROM node:22-alpine@sha256:[a-f0-9]{64} AS production$/mu);
  assert.match(productionDockerfile, /\nUSER node:node\nEXPOSE 3000 3001 3003\nCMD \["npm", "run", "start", "--workspace", "@virki\/hub"\]\s*$/u);
  assert.doesNotMatch(productionDockerfile, /staging-db-trust|virki_staging_db_root_ca|VIRKI_STAGING_APPROVED_DB_CA_SHA256|staging-db-root\.pem/u,
    "the production Dockerfile must have no staging CA layer, secret, or altered default target");
  assert.match(source, /^ARG VIRKI_STAGING_APPROVED_BASE_IMAGE\nFROM \$\{VIRKI_STAGING_APPROVED_BASE_IMAGE\} AS staging-db-trust\nARG VIRKI_STAGING_APPROVED_BASE_IMAGE\nARG VIRKI_STAGING_APPROVED_DB_CA_SHA256\nUSER root\n/mu,
    "no default base image, image tag, or unpinned parent may be chosen");
  assert.doesNotMatch(source, /^ARG (?:VIRKI_STAGING_APPROVED_BASE_IMAGE|VIRKI_STAGING_APPROVED_DB_CA_SHA256)=/mu);
  const stage = source;
  assert.match(stage, /RUN --mount=type=secret,id=virki_staging_db_root_ca,required=true \\$/mu,
    "BuildKit must refuse missing CA secret");
  assert.match(stage, /if \(!\/\^ghcr\\\.io\\\/bielxdh3\\\/virki-runtime@sha256:\[a-f0-9\]\{64\}\$\/u\.test\(approvedBase \?\? ""\)\)/u,
    "base must be the separately approved Virki runtime image pinned by lowercase OCI SHA256");
  assert.match(stage, /if \(!\/\^\[a-f0-9\]\{64\}\$\/u\.test\(expected \?\? ""\)\)/u,
    "only a lowercase 64-digit explicit approved SHA256 is acceptable");
  assert.match(stage, /statSync\(secretPath\)\.size/u, "bound the secret before reading");
  assert.match(stage, /createHash\("sha256"\)\.update\(source\)\.digest\("hex"\) !== expected/u,
    "verify exact secret bytes before installing the CA");
  assert.match(stage, /new X509Certificate\(match\[0\]\)/u, "parse actual X.509 certificates");
  assert.match(stage, /!certificate\.ca/u, "reject non-CA certificates");
  assert.match(stage, /!certificate\.raw\.equals\(der\)/u, "reject trailing data in decoded DER");
  assert.match(stage, /count === 0 \|\| end !== pem\.length/u, "reject zero certificates and any extra PEM material");
  assert.match(stage, /writeFileSync\("\/app\/ca\/staging-db-root\.pem", source, \{ flag: "wx", mode: 0o444 \}\)/u);
  assert.match(stage, /chmodSync\("\/app\/ca\/staging-db-root\.pem", 0o444\)/u);
  assert.match(stage, /LABEL org\.virki\.staging\.db-root-ca\.sha256="\$\{VIRKI_STAGING_APPROVED_DB_CA_SHA256\}"\nUSER node:node\s*$/u);
  assert.doesNotMatch(stage, /NODE_TLS_REJECT_UNAUTHORIZED|NODE_EXTRA_CA_CERTS|ENV DATABASE_URL|ARG DATABASE_URL|COPY\s+[^\n]*\.pem/u,
    "the CA is not silently installed into global TLS or copied from the build context");
  return stage;
}

function inlineVerifier(stage) {
  const match = stage.match(/RUN --mount=type=secret,id=virki_staging_db_root_ca,required=true \\\r?\n\s*node -e '([\s\S]*?)' "\$VIRKI_STAGING_APPROVED_BASE_IMAGE" "\$VIRKI_STAGING_APPROVED_DB_CA_SHA256"/u);
  assert.ok(match, "the staging target must call Node only after the required BuildKit mount");
  const script = match[1].replace(/\\\r?\n\s*/gu, " ");
  assert.doesNotThrow(() => new Function(script), "the actual in-image verifier must parse as JavaScript");
  return script;
}

function publicCaFixture() {
  for (const certificate of rootCertificates) {
    const pem = certificate.trimEnd().replace(/\r\n/gu, "\n") + "\n";
    const parsed = new X509Certificate(pem);
    if (parsed.ca && Date.parse(parsed.validFrom) <= Date.now() && Date.parse(parsed.validTo) > Date.now()) return pem;
  }
  throw new Error("No currently valid public test CA bundled with this local Node runtime");
}

test("staging CA target is isolated; missing mount or SHA guard fails the static contract", () => {
  assertImageContract(dockerfile);
  for (const mutation of [
    dockerfile.replace("FROM ${VIRKI_STAGING_APPROVED_BASE_IMAGE}", "FROM node:22-alpine"),
    dockerfile.replace("ARG VIRKI_STAGING_APPROVED_BASE_IMAGE\n", "ARG VIRKI_STAGING_APPROVED_BASE_IMAGE=node:22-alpine\n"),
    dockerfile.replace("ghcr\\.io\\/bielxdh3\\/virki-runtime@sha256:", ".*@sha256:"),
    dockerfile.replace("ARG VIRKI_STAGING_APPROVED_DB_CA_SHA256\n", ""),
    dockerfile.replace("required=true", "required=false"),
    dockerfile.replace("required=true", ""),
    dockerfile.replace("id=virki_staging_db_root_ca", "id=other_ca"),
    dockerfile.replace("^[a-f0-9]{64}$", ".*"),
    dockerfile.replace('!== expected) throw Error("Staging database CA digest mismatch")', '=== expected) throw Error("Staging database CA digest mismatch")'),
    dockerfile.replace("!certificate.ca", "false"),
    dockerfile.replace("end !== pem.length", "false"),
    dockerfile.replace("mode: 0o444", "mode: 0o666"),
    dockerfile.replace(/USER node:node\s*$/u, "USER root")
  ]) {
    assert.throws(() => assertImageContract(mutation), "unsafe mutation must fail the source contract");
  }
});

test("actual inline CA verifier accepts approved public roots, but rejects absent, mismatched, malformed or extra PEM material", (t) => {
  const stage = assertImageContract(dockerfile);
  const source = inlineVerifier(stage);
  const temporary = mkdtempSync(path.join(tmpdir(), "virki-staging-db-ca-"));
  t.after(() => rmSync(temporary, { recursive: true, force: true }));
  const sourceFile = path.join(temporary, "secret.pem");
  const destinationDir = path.join(temporary, "ca");
  const destinationFile = path.join(destinationDir, "staging-db-root.pem");

  // Only the paths are swapped for offline inspection. The crypto, PEM, digest
  // and install verifier is the exact JavaScript embedded in the Dockerfile.
  const verifier = source
    .replaceAll(JSON.stringify(imageSecret), JSON.stringify(sourceFile))
    .replaceAll(JSON.stringify(imageCaDirectory), JSON.stringify(destinationDir))
    .replaceAll(JSON.stringify(imageCa), JSON.stringify(destinationFile));
  assert.notEqual(verifier, source, "offline verifier must use disposable paths");
  function run(bytes, approvedDigest = bytes === null ? "a".repeat(64) : digest(bytes), baseImage = approvedBase) {
    if (existsSync(destinationFile)) rmSync(destinationFile);
    if (bytes === null) {
      if (existsSync(sourceFile)) rmSync(sourceFile);
    } else {
      writeFileSync(sourceFile, bytes);
    }
    const child = spawnSync(process.execPath, ["-e", verifier, baseImage, approvedDigest], {
      cwd: temporary, encoding: "utf8", timeout: 10000
    });
    assert.equal(child.error, undefined, child.error?.message);
    return child;
  }
  const pem = publicCaFixture();
  const approved = Buffer.from(pem, "utf8");
  assert.equal(run(approved).status, 0, "known public trust root must pass");
  assert.deepEqual(readFileSync(destinationFile), approved);
  for (const badBase of [
    "", "ghcr.io/bielxdh3/virki-runtime:latest", "node:22-alpine@sha256:" + "b".repeat(64),
    "ghcr.io/attacker/virki-runtime@sha256:" + "b".repeat(64),
    "ghcr.io/bielxdh3/virki-runtime@sha256:" + "B".repeat(64),
    "ghcr.io/bielxdh3/virki-runtime@sha256:" + "a".repeat(63)
  ]) assert.equal(run(approved, digest(approved), badBase).status, 1, "unapproved, mutable or malformed base image rejected");
  assert.equal(run(Buffer.from(pem + pem)).status, 1, "duplicated CA is not acceptable");
  assert.equal(run(null).status, 1, "absent BuildKit secret equivalent fails");
  assert.equal(run(approved, "F".repeat(64)).status, 1, "uppercase SHA is rejected");
  assert.equal(run(approved, "").status, 1, "missing approved SHA is rejected");
  assert.equal(run(approved, "f".repeat(63)).status, 1, "short approved SHA is rejected");
  assert.equal(run(approved, "f".repeat(64)).status, 1, "wrong approved SHA is rejected");
  const bogusPrivateKeyPem = ["-----BEGIN", "PRIVATE KEY-----\naGVsbG8=\n-----END", "PRIVATE KEY-----\n"].join(" ");
  for (const altered of [
    Buffer.from(pem + bogusPrivateKeyPem),
    Buffer.from(pem + "EXTRA\n"),
    Buffer.from("EXTRA\n" + pem),
    Buffer.from(pem.replace(/\n/gu, "\r\n")),
    Buffer.from(pem.replace("BEGIN CERTIFICATE", "BEGIN PRIVATE KEY")),
    Buffer.from("-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n"),
    Buffer.from([0xff, 0xfe, 0xfd]),
    Buffer.alloc(131073, 0x41)
  ]) {
    const result = run(altered);
    assert.notEqual(result.status, 0, "noncanonical, invalid or extraneous certificate material is rejected");
    assert.equal(existsSync(destinationFile), false, "rejected input must never install the trust anchor");
  }
});
