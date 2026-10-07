export function getSessionCookieName(env: { NODE_ENV?: string } = process.env): string {
  return env.NODE_ENV === "production" ? "__Host-virki_session" : "virki_session";
}

export function getDeviceCookieName(env: { NODE_ENV?: string } = process.env): string {
  return env.NODE_ENV === "production" ? "__Host-virki_device" : "virki_device";
}

export const SESSION_COOKIE_NAME = getSessionCookieName();
export const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7;
export const DEVICE_COOKIE_NAME = getDeviceCookieName();
