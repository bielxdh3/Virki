import { recordInstalledHostWitnessManualIntent } from "../infra/offline/host-witness-ledger-activation-bridge.mjs";

// Root-installed Linux operator command. No caller-supplied pins, TLS target,
// witness private key, Docker handle, activation callback, or release action.
// In production the only input is /etc/virki/offline-witness-proof.json (0600).
try {
  const result = await recordInstalledHostWitnessManualIntent(process.argv.slice(2));
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (result.reconciliationRequired) process.exitCode = 3;
} catch {
  process.stderr.write("Host witness manual activation intent refused\n");
  process.exitCode = 2;
}
