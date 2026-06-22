import { createHash, randomBytes } from "node:crypto";
import { hash, verify } from "@node-rs/argon2";
import { prisma } from "@bielos/database";

export const SESSION_COOKIE_NAME = "bielos_session";
export const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7;

const SESSION_TOKEN_BYTES = 32;
const DUMMY_PASSWORD_HASH =
  "$argon2id$v=19$m=65536,t=3,p=1$KWdtXzW0AylnuGwdi+AYHQ$/T76IyJJw69emqMKm2cc7E1k2lQFMBFp/qTumxvHvHw";

export type AuthenticatedUser = {
  id: string;
  email: string;
  displayName: string | null;
  role: string;
};

export type AuthenticatedSession = {
  id: string;
  expiresAt: Date;
  user: AuthenticatedUser;
};

export type CreatedSession = {
  token: string;
  expiresAt: Date;
};

export type SessionCookieOptions = {
  httpOnly: true;
  sameSite: "lax";
  secure: boolean;
  path: "/";
  expires: Date;
};

export type ExpiredSessionCookieOptions = {
  httpOnly: true;
  sameSite: "lax";
  secure: boolean;
  path: "/";
  expires: Date;
  maxAge: 0;
};

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export async function hashPassword(password: string): Promise<string> {
  return hash(password, {
    algorithm: 2,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 1,
    outputLen: 32
  });
}

export async function verifyPassword(passwordHash: string, password: string): Promise<boolean> {
  try {
    return await verify(passwordHash, password);
  } catch {
    return false;
  }
}

export function generateSessionToken(): string {
  return randomBytes(SESSION_TOKEN_BYTES).toString("base64url");
}

export function hashSessionToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

export function getSessionExpiresAt(now = new Date()): Date {
  return new Date(now.getTime() + SESSION_TTL_SECONDS * 1000);
}

export function getSessionCookieOptions(expiresAt: Date): SessionCookieOptions {
  return {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    expires: expiresAt
  };
}

export function getExpiredSessionCookieOptions(): ExpiredSessionCookieOptions {
  return {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    expires: new Date(0),
    maxAge: 0
  };
}

export async function authenticateUser(
  email: string,
  password: string
): Promise<AuthenticatedUser | null> {
  const user = await prisma.user.findUnique({
    where: { email: normalizeEmail(email) },
    select: {
      id: true,
      email: true,
      displayName: true,
      passwordHash: true,
      role: true,
      isActive: true
    }
  });

  if (!user?.isActive || !user.passwordHash) {
    await verifyPassword(DUMMY_PASSWORD_HASH, password);
    return null;
  }

  const passwordMatches = await verifyPassword(user.passwordHash, password);

  if (!passwordMatches) {
    return null;
  }

  return {
    id: user.id,
    email: user.email,
    displayName: user.displayName,
    role: user.role
  };
}

export async function createSession(userId: string): Promise<CreatedSession> {
  const token = generateSessionToken();
  const tokenHash = hashSessionToken(token);
  const expiresAt = getSessionExpiresAt();

  await prisma.session.create({
    data: {
      userId,
      tokenHash,
      expiresAt
    }
  });

  return { token, expiresAt };
}

export async function getSessionByToken(token: string): Promise<AuthenticatedSession | null> {
  const tokenHash = hashSessionToken(token);
  const session = await prisma.session.findUnique({
    where: { tokenHash },
    include: {
      user: {
        select: {
          id: true,
          email: true,
          displayName: true,
          role: true,
          isActive: true
        }
      }
    }
  });

  if (!session || session.revokedAt || session.expiresAt <= new Date() || !session.user.isActive) {
    return null;
  }

  return {
    id: session.id,
    expiresAt: session.expiresAt,
    user: {
      id: session.user.id,
      email: session.user.email,
      displayName: session.user.displayName,
      role: session.user.role
    }
  };
}

export async function revokeSessionToken(token: string): Promise<void> {
  await prisma.session.updateMany({
    where: {
      tokenHash: hashSessionToken(token),
      revokedAt: null
    },
    data: {
      revokedAt: new Date()
    }
  });
}
