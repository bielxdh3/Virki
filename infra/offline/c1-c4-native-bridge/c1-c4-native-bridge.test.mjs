import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const THIS_DIR = path.dirname(fileURLToPath(import.meta.url));
const C4_DIR = path.resolve(THIS_DIR, "../native-owner-authority");
const LINUX_NATIVE_SKIP = process.platform !== "linux"
  ? "Linux-only native Go-to-C4 bridge integration test"
  : (typeof process.getuid === "function" && process.getuid() === 0
    ? "Non-root Linux user required for native C4 daemon test"
    : false);

function resolveGoBinary() {
  if (process.env.VIRKI_GO_BIN) {
    execFileSync(process.env.VIRKI_GO_BIN, ["version"], { stdio: "ignore" });
    return process.env.VIRKI_GO_BIN;
  }
  for (const bin of ["/usr/local/go/bin/go", "go"]) {
    try {
      execFileSync(bin, ["version"], { stdio: "ignore" });
      return bin;
    } catch (_err) {
      void _err;
    }
  }
  return null;
}

test("Native BuildKit Go-to-C4 bridge executes live VROA_V2 + sealed memfd lifecycle with SIGN_ACK=22", { skip: LINUX_NATIVE_SKIP }, async (t) => {
  const goBin = resolveGoBinary();
  assert.ok(goBin, "Go 1.26+ toolchain must be available (set VIRKI_GO_BIN or install /usr/local/go/bin/go)");

  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "virki-go-c4-bin-"));
  const runDir = fs.mkdtempSync(path.join(os.tmpdir(), "virki-go-c4-run-"));
  let proc = null;

  t.after(async () => {
    if (proc && proc.exitCode === null && proc.signalCode === null) {
      await new Promise((resolve) => {
        const killTimer = setTimeout(() => { proc.kill("SIGKILL"); }, 3000);
        proc.once("exit", () => { clearTimeout(killTimer); resolve(); });
        proc.kill("SIGTERM");
      });
    }
    fs.rmSync(binDir, { recursive: true, force: true });
    fs.rmSync(runDir, { recursive: true, force: true });
  });

  const gccFlags = [
    "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
    "-D_FORTIFY_SOURCE=2", "-fstack-protector-strong", "-fPIE", "-pie", "-Wl,-z,relro,-z,now",
  ];
  const srvBin = path.join(binDir, "native-owner-authority");
  execFileSync("/usr/bin/gcc", [...gccFlags, path.join(C4_DIR, "native-owner-authority.c"), "-o", srvBin]);

  const sockPath = path.join(runDir, "owner.sock");
  const ledgerDir = path.join(runDir, "ledger");
  fs.mkdirSync(ledgerDir, { mode: 0o700 });

  proc = spawn(srvBin, ["--socket", sockPath, "--ledger-dir", ledgerDir, "--dev-allow-same-uid"], {
    stdio: ["ignore", "pipe", "inherit"],
  });

  await new Promise((resolve, reject) => {
    let out = "";
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) { settled = true; proc.kill("SIGKILL"); reject(new Error("C4 daemon startup timeout")); }
    }, 5000);
    proc.stdout.on("data", (d) => {
      out += d.toString("utf8");
      if (!settled && out.includes("VIRKI_OWNER_AUTHORITY_READY:") && out.includes("\n")) {
        settled = true; clearTimeout(timer); resolve();
      }
    });
    proc.on("error", (err) => { if (!settled) { settled = true; clearTimeout(timer); reject(err); } });
    proc.on("exit", (code, sig) => { if (!settled) { settled = true; clearTimeout(timer); reject(new Error(`C4 daemon exited: ${code}/${sig}`)); } });
  });

  const goOut = execFileSync(goBin, ["test", "-v", "-count=1", "./..."], {
    cwd: THIS_DIR,
    encoding: "utf8",
    env: {
      ...process.env,
      GOPROXY: "off",
      GOSUMDB: "off",
      GOTOOLCHAIN: "local",
      GOCACHE: path.join(runDir, "gocache"),
      VIRKI_C4_TEST_SOCKET: sockPath,
    },
  });
  assert.match(goOut, /PASS:\s+TestVROAV2ABISizes/);
  assert.match(goOut, /PASS:\s+TestBuildC4RequestPositiveAndRejections/);
  assert.match(goOut, /PASS:\s+TestLiveGoToNativeC4DaemonBridge/);
});
