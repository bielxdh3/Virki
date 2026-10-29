import { inspectInstalledManualSupervisorReadiness } from
  "../infra/offline/native-supervisor/owner-installed-manual-supervisor.mjs";

// Fixed root-installed read-only inspector. Production takes NO user input,
// owner keys, source paths, injected executor, Docker endpoint or override.
// Every result has a nonzero exit status because the native trust closure,
// independent off-host floor and physical writer/PG proofs are not established.
try {
  if (process.argv.length !== 2) throw new Error("unexpected caller arguments");
  const result = inspectInstalledManualSupervisorReadiness();
  if (result.deployAuthorized !== false || result.rollbackAuthorized !== false ||
      result.resumeWritersAuthorized !== false) throw new Error("authority invariant");
  process.stdout.write("Manual native supervisor: evidence inspected; authorization BLOCKED.\n");
} catch {
  process.stderr.write("Manual native supervisor refused; authorization BLOCKED.\n");
}
process.exitCode = 2;
