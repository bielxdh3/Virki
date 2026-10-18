import assert from "node:assert/strict";
import test from "node:test";
import { buildE2ECommand } from "./run-e2e.mjs";

test("Windows runs browser E2E in isolated Linux Docker and carries filters as JSON data", () => {
  const playwrightArguments = ["--grep", "OIDC flow with spaces", "value; do-not-run-shell"];
  const command = buildE2ECommand("win32", playwrightArguments, "C:\\Virki");

  assert.equal(command.executable, "powershell.exe");
  assert.deepEqual(command.args, [
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-File",
    "C:\\Virki\\scripts\\e2e\\run-isolated-linux-docker.ps1",
    "-E2EOnly"
  ]);
  assert.deepEqual(JSON.parse(command.environment.VIRKI_E2E_PLAYWRIGHT_ARGUMENTS_JSON), playwrightArguments);
});

test("Linux executes the repository Playwright CLI directly with argv boundaries preserved", () => {
  const playwrightArguments = ["--grep", "OIDC flow with spaces"];
  const command = buildE2ECommand("linux", playwrightArguments, "/workspace/virki");

  assert.equal(command.executable, process.execPath);
  assert.deepEqual(command.args, [
    "/workspace/virki/node_modules/playwright/cli.js",
    "test",
    "--config=playwright.config.mts",
    ...playwrightArguments
  ]);
  assert.deepEqual(command.environment, {});
});
