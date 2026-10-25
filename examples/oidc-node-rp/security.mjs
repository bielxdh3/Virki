import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes, timingSafeEqual } from 'node:crypto';

export const PREAUTH_COOKIE = '__Host-virki-rp-preauth';
export const SESSION_COOKIE = '__Host-virki-rp-session';
const OPAQUE_ID = /^[A-Za-z0-9_-]{43}$/u;
const MAX_SESSION_SECONDS = 8 * 60 * 60;

export function randomId() { return randomBytes(32).toString('base64url'); }
export function hashId(value) { return createHash('sha256').update(value).digest('hex'); }
export function validId(value) { return typeof value === 'string' && OPAQUE_ID.test(value); }

export function parseCookie(header, name) {
  if (typeof header !== 'string' || header.length > 8192) return null;
  const values = header.split(';').map(v => v.trim()).filter(v => v.startsWith(`${name}=`));
  if (values.length !== 1) return null;
  const value = values[0].slice(name.length + 1);
  return validId(value) ? value : null;
}

export function sessionCookie(name, value, seconds = MAX_SESSION_SECONDS) {
  if (![PREAUTH_COOKIE, SESSION_COOKIE].includes(name) || !validId(value) || !Number.isSafeInteger(seconds) || seconds < 1 || seconds > MAX_SESSION_SECONDS) throw new Error('Invalid RP session cookie.');
  return `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${seconds}`;
}

export function clearCookie(name) {
  if (![PREAUTH_COOKIE, SESSION_COOKIE].includes(name)) throw new Error('Invalid RP session cookie.');
  return `${name}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`;
}

export function acceptedPost(req, origin) {
  // Browsers send Origin for POST; disallow its absence (including scripted requests).
  const suppliedOrigin = req.headers.origin;
  const fetchSite = req.headers['sec-fetch-site'];
  return typeof suppliedOrigin === 'string' && suppliedOrigin === origin
    && (fetchSite === undefined || fetchSite === 'same-origin')
    && req.headers['content-type']?.split(';', 1)[0]?.trim().toLowerCase() === 'application/x-www-form-urlencoded';
}

export function parseServerOrigin(value) {
  if (typeof value !== 'string' || value.trim() !== value) throw new Error('RP_ORIGIN must be exact HTTPS origin.');
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.origin !== value || url.username || url.password || url.search || url.hash) throw new Error('RP_ORIGIN must be exact HTTPS origin.');
  return url;
}

export function sessionCryptoKey(flowKey) {
  if (!(flowKey instanceof Uint8Array) || flowKey.byteLength !== 32) throw new Error('Invalid RP encryption key.');
  return Buffer.from(hkdfSync('sha256', flowKey, Buffer.from('virki-rp-session-v1'), Buffer.from('server-only-token-encryption'), 32));
}

export function encryptToken(token, key, idHash) {
  if (typeof token !== 'string' || !token || token.length > 8192 || !/^[a-f0-9]{64}$/u.test(idHash)) throw new Error('Invalid RP token.');
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(`virki-rp-session-v1:${idHash}`));
  const data = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()]);
  return ['v1', iv.toString('base64url'), cipher.getAuthTag().toString('base64url'), data.toString('base64url')].join('.');
}

export function decryptToken(payload, key, idHash) {
  if (typeof payload !== 'string' || payload.length > 16000 || !/^[a-f0-9]{64}$/u.test(idHash)) throw new Error('Invalid RP token payload.');
  const [version, iv, tag, data, extra] = payload.split('.');
  if (version !== 'v1' || !iv || !tag || !data || extra !== undefined) throw new Error('Invalid RP token payload.');
  const ivBytes = Buffer.from(iv, 'base64url');
  const tagBytes = Buffer.from(tag, 'base64url');
  if (ivBytes.length !== 12 || tagBytes.length !== 16) throw new Error('Invalid RP token payload.');
  const decipher = createDecipheriv('aes-256-gcm', key, ivBytes, { authTagLength: 16 });
  decipher.setAAD(Buffer.from(`virki-rp-session-v1:${idHash}`));
  decipher.setAuthTag(tagBytes);
  return Buffer.concat([decipher.update(Buffer.from(data, 'base64url')), decipher.final()]).toString('utf8');
}

export function identicalHash(a, b) {
  if (!/^[a-f0-9]{64}$/u.test(a ?? '') || !/^[a-f0-9]{64}$/u.test(b ?? '')) return false;
  return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

export function escapeHtml(value) {
  return String(value).replace(/[&<>"']/gu, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]);
}
