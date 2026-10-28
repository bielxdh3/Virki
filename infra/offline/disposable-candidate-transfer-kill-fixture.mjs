import { rehearseDisposableCandidateTransfer } from "./disposable-candidate-transfer-fixture.mjs";

// Invoked only by the disposable test runner. Deliberately terminates THIS
// disposable child, allowing the parent to inspect the fsynced orphan latch.
if (process.env.VIRKI_OFFLINE_TRANSFER_FIXTURE !== "1" ||
  process.env.VIRKI_OFFLINE_TRANSFER_KILL_TEST !== "1" ||
  process.platform !== "linux" || process.getuid?.() !== 0) {
  throw new Error("disposable kill fixture refused");
}
const request = JSON.parse(process.env.VIRKI_OFFLINE_TRANSFER_REQUEST ?? "null");
await rehearseDisposableCandidateTransfer(request, {
  onPhase(phase) {
    if (phase === "chunkCopied") process.kill(process.pid, "SIGKILL");
  },
});
