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
  } catch {
    context.status = 400;
    context.body = { error: "invalid_request" };
    return { ok: false };
  }
}
