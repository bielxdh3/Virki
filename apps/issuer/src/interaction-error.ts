import { errors } from "oidc-provider";

type InteractionResponseContext = {
  status: number;
  body: unknown;
};

export type InteractionDetailsResult<T> = { ok: true; value: T } | { ok: false };

export async function readInteractionDetailsOrRespond<T>(
  context: InteractionResponseContext,
  read: () => Promise<T>
): Promise<InteractionDetailsResult<T>> {
  try {
    return { ok: true, value: await read() };
  } catch (error) {
    // Expired or absent interaction cookies are client errors. An adapter or
    // database failure is not: answering 400 would disguise an outage as a
    // malformed login and prevent clients from retrying appropriately.
    const missingSession = error instanceof errors.SessionNotFound;
    context.status = missingSession ? 400 : 503;
    context.body = { error: missingSession ? "invalid_request" : "temporarily_unavailable" };
    return { ok: false };
  }
}
