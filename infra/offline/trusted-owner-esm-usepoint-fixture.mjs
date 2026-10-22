import { existsSync, readFileSync, renameSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { statfsSync } from "node:fs";
import {
  rehearseInstalledVerifierPinnedEsmImport,
} from "./trusted-owner-installation.mjs";

// Direct subprocess fixture ONLY. It never executes the imported verifier's
// release methods, and it cannot select a native production filesystem.
if (process.platform !== "linux" || process.arch !== "x64" ||
  process.getuid?.() !== 0 || !existsSync("/.dockerenv") ||
  statfsSync(os.tmpdir()).type !== 0x01021994 ||
  process.env.VIRKI_OWNER_INSTALL_DISPOSABLE_FIXTURE !== "1") {
  throw new Error("Native disposable Linux root fixture required");
}
const request = JSON.parse(process.env.VIRKI_USEPOINT_REQUEST ?? "null");
const mutation = process.env.VIRKI_USEPOINT_MUTATION ?? "none";
if (!["none", "swap-entry", "swap-dependency", "remove-entry",
  "symlink-entry"].includes(mutation)) {
  throw new Error("Unreviewed fixture mutation");
}
const target = ["swap-entry", "remove-entry", "symlink-entry"].includes(mutation) ?
  "infra/offline/trusted-host-entry.mjs" :
  "scripts/lib/offline-release-attestation.mjs";
const result = await rehearseInstalledVerifierPinnedEsmImport(request, {
  afterSnapshot() {
    if (mutation === "none") return;
    const file = path.join(request.fixtureRoot, "installed-code", "offline-release",
      ...target.split("/"));
    const original = readFileSync(file);
    renameSync(file, file + ".before-swap");
    if (mutation === "remove-entry") return;
    if (mutation === "symlink-entry") {
      symlinkSync(file + ".before-swap", file);
      return;
    }
    // Should never reach the Node compiler: a post-measurement in-place swap.
    writeFileSync(file, "// malicious shadow source\n", { mode: 0o600 });
    if (original.length === 0) throw new Error("invalid genuine ESM fixture");
  },
});
process.stdout.write(JSON.stringify(result) + "\n");
