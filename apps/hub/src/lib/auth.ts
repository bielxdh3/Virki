import { cookies } from "next/headers";
import {
  getSessionByToken,
  SESSION_COOKIE_NAME,
  type AuthenticatedSession
} from "@bielos/auth";

export async function getCurrentSession(): Promise<AuthenticatedSession | null> {
  const cookieStore = await cookies();
  const sessionToken = cookieStore.get(SESSION_COOKIE_NAME)?.value;

  if (!sessionToken) {
    return null;
  }

  return getSessionByToken(sessionToken);
}
