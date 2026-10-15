import assert from "node:assert/strict";
import { test } from "node:test";
import { selectGhcrReadCredential } from "./lib/ghcr-evidence.mjs";

test("unattended deployments require a distinct dedicated GHCR read token", () => {
  assert.throws(
    () => selectGhcrReadCredential({ GH_TOKEN: "fine-grained-repository-read", VIRKI_AUTOMATED_DEPLOY_ENABLED: "true" }),
    (error) => error.code === "COMMAND_FAILED"
  );
  assert.throws(
    () => selectGhcrReadCredential({ VIRKI_AUTOMATED_DEPLOY_ENABLED: "true", VIRKI_GHCR_READ_TOKEN: "bad\nsecret" }),
    (error) => error.code === "COMMAND_FAILED"
  );
});

test("GHCR token is scoped to package API calls, not repository and CI reads", () => {
  const originalRepositoryToken = process.env.GH_TOKEN;
  const auth = selectGhcrReadCredential({
    GH_TOKEN: "fine-grained-repository-read",
    VIRKI_GHCR_READ_TOKEN: "classic-packages-read-only",
    VIRKI_AUTOMATED_DEPLOY_ENABLED: "true"
  });
  assert.equal(auth.token, "classic-packages-read-only");
  assert.equal(auth.apiOptions.env.GH_TOKEN, "classic-packages-read-only");
  assert.equal(process.env.GH_TOKEN, originalRepositoryToken);
});

test("explicitly disabled automation retains current interactive authentication behavior", () => {
  assert.deepEqual(selectGhcrReadCredential({}), { token: null, apiOptions: {} });
});
