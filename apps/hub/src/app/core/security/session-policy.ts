export function canRevokeOtherSession(currentSessionId: string, targetSessionId: string): boolean {
  return (
    targetSessionId.length > 0 &&
    targetSessionId.length <= 128 &&
    targetSessionId !== currentSessionId
  );
}

export function isRevokeAllOtherSessionsConfirmed(value: string): boolean {
  return value === "yes";
}
