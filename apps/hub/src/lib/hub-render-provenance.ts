import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export const HUB_RENDER_PROVENANCE_HEADER = "x-virki-hub-render-proof";
const PROOF_LIFETIME_MS = 120_000;
const FUTURE_SKEW_MS = 30_000;

function sign(key: string, timestamp: string, nonce: string, sessionToken: string): string {
  const boundSession = createHash("sha256").update(sessionToken).digest("hex");
  return createHmac("sha256", Buffer.from(key, "hex"))
    .update("virki-hub-render-v1\0")
    .update(timestamp).update("\0").update(nonce).update("\0").update(boundSession)
    .digest("base64url");
}

export function createHubRenderProof(sessionToken: string | undefined, env: Readonly<Record<string, string | undefined>> = process.env, now = Date.now()): string | null {
  const key = env.VIRKI_CSRF_SIGNING_KEY;
  if (!sessionToken || !key || !/^[a-f0-9]{64}$/iu.test(key) || !Number.isSafeInteger(now)) return null;
  const timestamp = String(now);
  const nonce = randomBytes(12).toString("base64url");
  return `v1.${timestamp}.${nonce}.${sign(key, timestamp, nonce, sessionToken)}`;
}

export function verifyHubRenderProof(proof: string | null | undefined, sessionToken: string | undefined, env: Readonly<Record<string, string | undefined>> = process.env, now = Date.now()): boolean {
  if (!proof || !sessionToken || proof.length > 150 || !Number.isSafeInteger(now)) return false;
  const parts = proof.split(".");
  if (parts.length !== 4 || parts[0] !== "v1" || !/^(?:0|[1-9][0-9]{0,15})$/u.test(parts[1]) ||
      !/^[A-Za-z0-9_-]{16}$/u.test(parts[2]) || !/^[A-Za-z0-9_-]{43}$/u.test(parts[3])) return false;
  const created = Number(parts[1]);
  if (!Number.isSafeInteger(created) || now - created > PROOF_LIFETIME_MS || created - now > FUTURE_SKEW_MS) return false;
  return [env.VIRKI_CSRF_SIGNING_KEY, env.VIRKI_CSRF_SIGNING_KEY_PREVIOUS].some((key) => {
    if (!key || !/^[a-f0-9]{64}$/iu.test(key)) return false;
    const expected = Buffer.from(sign(key, parts[1], parts[2], sessionToken), "utf8");
    const received = Buffer.from(parts[3], "utf8");
    return expected.length === received.length && timingSafeEqual(expected, received);
  });
}
