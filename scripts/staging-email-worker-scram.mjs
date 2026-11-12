import { createHash, createHmac, pbkdf2Sync, randomBytes, timingSafeEqual } from "node:crypto";

// PostgreSQL SCRAM verifier; the plaintext password must NEVER enter SQL.
// The returned verifier is still sensitive: store it through the authorized
// operator-owned secret channel, never in logs, commits or chat.
export function createEmailWorkerScramVerifier(password, salt = randomBytes(16)) {
  if (!/^[0-9a-fA-F]{64}$/u.test(password)) {
    throw new Error("Worker password must be 64 hexadecimal characters.");
  }
  if (!Buffer.isBuffer(salt) || salt.length !== 16) throw new Error("SCRAM salt must be 16 random bytes.");
  const iterations = 4096;
  const passwordBytes = Buffer.from(password, "utf8");
  let saltedPassword;
  try {
    saltedPassword = pbkdf2Sync(passwordBytes, salt, iterations, 32, "sha256");
  } finally {
    passwordBytes.fill(0);
  }
  const clientKey = createHmac("sha256", saltedPassword).update("Client Key").digest();
  const storedKey = createHash("sha256").update(clientKey).digest();
  const serverKey = createHmac("sha256", saltedPassword).update("Server Key").digest();
  saltedPassword.fill(0);
  clientKey.fill(0);
  return `SCRAM-SHA-256$${iterations}:${salt.toString("base64")}$${storedKey.toString("base64")}:${serverKey.toString("base64")}`;
}

// Operator-side preflight: check the EXACT password/verifier pair without
// exposing either secret to PostgreSQL DDL logs or command-line arguments.
export function matchesEmailWorkerScramVerifier(password, verifier) {
  if (typeof verifier !== "string") return false;
  const match = /^SCRAM-SHA-256\$4096:([A-Za-z0-9+/]{22}==)\$[A-Za-z0-9+/]{43}=:[A-Za-z0-9+/]{43}=$/u.exec(verifier);
  if (!match) return false;
  const salt = Buffer.from(match[1], "base64");
  if (salt.length !== 16 || salt.toString("base64") !== match[1]) return false;
  const expected = Buffer.from(createEmailWorkerScramVerifier(password, salt), "utf8");
  const supplied = Buffer.from(verifier, "utf8");
  return expected.length === supplied.length && timingSafeEqual(expected, supplied);
}

if (process.argv[1]?.replaceAll("\\", "/").endsWith("/staging-email-worker-scram.mjs")) {
  const generate = process.env.VIRKI_GENERATE_EMAIL_WORKER_SCRAM === "operator-approved";
  const verify = process.env.VIRKI_VERIFY_EMAIL_WORKER_SCRAM === "operator-approved";
  if (generate === verify) throw new Error("Choose exactly one operator-approved SCRAM operation.");
  const operatorCredential = process.env.VIRKI_EMAIL_WORKER_DB_PASSWORD;
  if (!operatorCredential) throw new Error("Worker password must come from a controlled secret environment.");
  if (verify) {
    if (!matchesEmailWorkerScramVerifier(operatorCredential, process.env.VIRKI_EMAIL_WORKER_DB_SCRAM_VERIFIER)) {
      throw new Error("Worker SCRAM password/verifier mismatch; refuse provisioning.");
    }
    process.stdout.write("SCRAM_VERIFIER_PAIR=VALID\n");
  } else {
    process.stdout.write(createEmailWorkerScramVerifier(operatorCredential) + "\n");
  }
}
