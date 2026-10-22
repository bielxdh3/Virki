import assert from "node:assert/strict";
import test from "node:test";
import { cleanupOwnedDockerResources } from "./lib/disposable-docker-cleanup.mjs";

const OWNER = "validation-worker15-123";
const LABEL = "org.virki.validation";
const CONTAINER_ID = "a".repeat(64);
const NETWORK_ID = "b".repeat(64);

function fixture({ foreign = false, removeFailure = false, inspectFailure = false, missing = false,
  staleAfterRemoval = false, invalidInspect = false } = {}) {
  const calls = [];
  const invoke = (args) => {
    calls.push(args);
    const [kind, operation, target] = args;
    if (operation === "inspect") {
      if (inspectFailure) return { status: 1, stdout: "", stderr: "permission denied" };
      if (missing || ((target === CONTAINER_ID || target === NETWORK_ID) && !staleAfterRemoval)) {
        return { status: 1, stdout: "", stderr: `Error: No such object: ${target}` };
      }
      if (invalidInspect) return { status: 0, stdout: "[]", stderr: "" };
      const isContainer = kind === "container";
      const value = isContainer
        ? { Id: CONTAINER_ID, Name: "/test-container", Config: { Labels: { [LABEL]: foreign ? "unrelated-owner" : OWNER } } }
        : { Id: NETWORK_ID, Name: "test-network", Labels: { [LABEL]: foreign ? "unrelated-owner" : OWNER } };
      return { status: 0, stdout: JSON.stringify([value]), stderr: "" };
    }
    if (operation === "rm") return { status: removeFailure ? 1 : 0, stdout: "", stderr: removeFailure ? "Docker rm failed" : "" };
    throw Error(`Unexpected Docker command: ${args.join(" ")}`);
  };
  return { calls, invoke };
}

test("cleanup removes only verified owner resources by immutable Docker IDs", () => {
  const f = fixture();
  cleanupOwnedDockerResources({ invoke: f.invoke, owner: OWNER, containers: ["test-container"], network: "test-network" });
  assert.deepEqual(f.calls.filter((args) => args[1] === "rm"), [
    ["container", "rm", "--force", "--volumes", CONTAINER_ID],
    ["network", "rm", NETWORK_ID],
  ]);
});

test("foreign owner blocks every deletion", () => {
  const f = fixture({ foreign: true });
  assert.throws(() => cleanupOwnedDockerResources({ invoke: f.invoke, owner: OWNER,
    containers: ["test-container"], network: "test-network" }), /cleanup refused/u);
  assert.equal(f.calls.filter((args) => args[1] === "rm").length, 0);
});

test("unknown inspection failure and rejected removals fail closed", () => {
  for (const options of [{ inspectFailure: true }, { removeFailure: true }]) {
    const f = fixture(options);
    assert.throws(() => cleanupOwnedDockerResources({ invoke: f.invoke, owner: OWNER,
      containers: ["test-container"], network: "test-network" }), /cleanup refused/u);
  }
});

test("absent resources are safe when exact Docker 'No such object' response is verified", () => {
  const f = fixture({ missing: true });
  cleanupOwnedDockerResources({ invoke: f.invoke, owner: OWNER,
    containers: ["test-container"], network: "test-network" });
  assert.equal(f.calls.filter((args) => args[1] === "rm").length, 0);
});

test("Docker false-success removal and malformed inspect responses fail closed", () => {
  for (const options of [{ staleAfterRemoval: true }, { invalidInspect: true }]) {
    const f = fixture(options);
    assert.throws(() => cleanupOwnedDockerResources({ invoke: f.invoke, owner: OWNER,
      containers: ["test-container"], network: "test-network" }), /cleanup refused/u);
  }
});
