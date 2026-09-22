const AUTH_COMMAND_FAILURE_MESSAGES = {
  "audit-cleanup": "Audit log cleanup failed.",
  "audit-recent": "Recent audit log inspection failed.",
  "email-worker": "Email worker failed.",
  "session-cleanup": "Inactive session cleanup failed."
} as const;

export type AuthCommandName = keyof typeof AUTH_COMMAND_FAILURE_MESSAGES;

export function getSafeAuthCommandFailureMessage(command: AuthCommandName): string {
  return AUTH_COMMAND_FAILURE_MESSAGES[command];
}

export async function runAuthCommand(
  command: AuthCommandName,
  operation: () => Promise<void>,
  disconnect: () => Promise<void>,
  writeError: (message: string) => void = console.error,
  setExitCode: (code: number) => void = (code) => {
    process.exitCode = code;
  }
): Promise<void> {
  let failed = false;

  try {
    await operation();
  } catch {
    failed = true;
  }

  try {
    await disconnect();
  } catch {
    failed = true;
  }

  if (failed) {
    writeError(getSafeAuthCommandFailureMessage(command));
    setExitCode(1);
  }
}
