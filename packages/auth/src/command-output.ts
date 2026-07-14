const AUTH_COMMAND_FAILURE_MESSAGES = {
  "audit-cleanup": "Audit log cleanup failed.",
  "audit-recent": "Recent audit log inspection failed.",
  "owner-seed": "OWNER seed failed.",
  "session-cleanup": "Inactive session cleanup failed."
} as const;

export type AuthCommandName = keyof typeof AUTH_COMMAND_FAILURE_MESSAGES;

export function getSafeAuthCommandFailureMessage(command: AuthCommandName): string {
  return AUTH_COMMAND_FAILURE_MESSAGES[command];
}
