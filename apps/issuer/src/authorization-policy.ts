export function requiresProjectAccessInteraction(
  accountId: string | undefined,
  clientId: string | undefined,
  hasActiveGrant: boolean
): boolean {
  return Boolean(accountId && clientId && !hasActiveGrant);
}

export function hasValidOidcStateAndNonce(state: string, nonce: string, requiresNonce: boolean): boolean {
  return isValidOpaqueValue(state) && (!requiresNonce || isValidOpaqueValue(nonce));
}

function isValidOpaqueValue(value: string): boolean {
  if (value.length < 16 || value.length > 512) return false;
  return !Array.from(value).some((character) => {
    const code = character.charCodeAt(0);
    return code <= 0x1f || code === 0x7f;
  });
}
