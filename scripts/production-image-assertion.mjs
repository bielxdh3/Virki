import { randomUUID } from "node:crypto";
import { createDisposableDockerSession } from "./lib/disposable-docker-session.mjs";
import { assertion } from "./lib/production-boundary-assertion.mjs";

const image = process.env.VIRKI_RUNTIME_IMAGE?.trim();
if (!image) {
  console.log(JSON.stringify({ status: "failed", errors: ["VIRKI_RUNTIME_IMAGE is required."] }));
  process.exit(1);
}



const owner = randomUUID();
const containerName = `virki-image-assertion-${owner}`;
const session = createDisposableDockerSession({
  kind: "runtime", owner, containers: [containerName], network: `virki-image-assertion-unused-${owner}`,
});
let passed = false;
let cleanupPassed;
try {
  session.mutate("run-assertion", ["run", "--rm", "--name", containerName,
    "--label", `org.virki.validation=${owner}`, "--network", "none",
    "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
    "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m", "--entrypoint", "node", image, "-e", assertion]);
  passed = true;
} catch {
  // A failed Docker run may have started despite losing its CLI response.
} finally {
  try { session.cleanup(); cleanupPassed = true; } catch { cleanupPassed = false; }
  try { session.finish(passed && cleanupPassed); } catch { cleanupPassed = false; }
}

if (!passed || !cleanupPassed) {
  console.log(JSON.stringify({ status: "failed", errors: ["Production image dependency boundary assertion failed."] }));
  process.exit(1);
}
console.log(JSON.stringify({ status: "passed", imageDependencyBoundary: true,
  disposableResourcesRemoved: true, disposableRunId: owner }));
