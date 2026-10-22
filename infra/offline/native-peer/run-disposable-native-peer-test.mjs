import path from "node:path";
import { fileURLToPath } from "node:url";
import { runOwnedLocalLinuxFixture } from "../disposable-local-docker.mjs";

// The Docker Engine only launches an isolated disposable fixture. Never
// mount the host daemon socket or host credentials. No production operations.
const IMAGE = "node:22.23.3-bookworm@sha256:0e5f906573693feaa1e21057ebdcfdb5bd5021f050b2dc7c9deceb629c7da2a8";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const args = [
  "run", "--rm", "--pull=never", "--platform=linux/amd64",
  "--network=none", "--read-only", "--cap-drop=ALL",
  "--security-opt=no-new-privileges", "--user", "0:0",
  "--pids-limit=128", "--memory=512m",
  // C probe executes only inside a transient private tmpfs, whereas all
  // project source files are bound read-only.
  "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=64m,mode=1777",
  "--mount", "type=bind,src=" + root + ",dst=/workspace,readonly",
  "--workdir", "/workspace",
  "--env", "VIRKI_DISPOSABLE_PEER_PROBE=1",
  IMAGE, "node", "--test", "infra/offline/native-peer/native-peer-probe.test.mjs",
];
try {
  runOwnedLocalLinuxFixture(args, { cwd: root, timeout: 45_000 });
} catch {
  process.stderr.write("Disposable Linux peer fixture refused or failed.\n");
  process.exitCode = 1;
}
