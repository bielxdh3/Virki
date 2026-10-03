export async function readBoundedFormData(request: Request, maxBytes = 16 * 1024): Promise<FormData | null> {
  const length = request.headers.get("content-length");
  if (length !== null && (!/^\d+$/u.test(length) || Number(length) > maxBytes)) return null;
  const reader = request.body?.getReader();
  if (!reader) return new FormData();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      total += part.value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        return null;
      }
      chunks.push(part.value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    const parsed = await new Response(body, { headers: { "content-type": request.headers.get("content-type") ?? "" } }).formData();
    for (const value of parsed.values()) if (typeof value !== "string") return null;
    return parsed;
  } catch {
    return null;
  }
}
