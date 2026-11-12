import { createHash, createHmac, pbkdf2Sync, randomBytes } from "node:crypto";

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

if (process.argv[1]?.replaceAll("\\", "/").endsWith("/staging-email-worker-scram.mjs")) {
  if (process.env.VIRKI_GENERATE_EMAIL_WORKER_SCRAM !== "operator-approved") {
    throw new Error("SCRAM generation requires the explicit operator-approved opt-in.");
  }
  const operatorCredential = process.env.VIRKI_EMAIL_WORKER_DB_PASSWORD;
  if (!operatorCredential) throw new Error("Worker password must come from a controlled secret environment.");
  process.stdout.write(createEmailWorkerScramVerifier(operatorCredential) + "\n");
}
