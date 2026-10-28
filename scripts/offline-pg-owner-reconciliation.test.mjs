import assert from "node:assert/strict";
import test from "node:test";
import { runWithDurablePgOwnerIntent } from "./lib/offline-pg-owner-reconciliation.mjs";

const owner = "a".repeat(32);
const name = `virki-disposable-pg-${owner}`;
const id = "b".repeat(64);
const missing = { status: 1, stderr: "Error: No such object", stdout: "" };
const found = { status: 0, stderr: "", stdout: `${id}|/${name}|${owner}\n` };

function fixture(overrides = {}) {
  const calls = [];
  const journal = {
    create: () => calls.push("create"),
    append: () => calls.push("append"),
    clear: () => calls.push("clear"),
  };
  const inputs = {
    name, owner, journal,
    launch: () => { calls.push("launch"); return { status: 0, error: undefined }; },
    inspect: () => { calls.push("inspect"); return missing; },
    remove: () => { calls.push("remove"); return { status: 0 }; },
    ...overrides,
  };
  return { calls, inputs };
}

test("lost Docker ACK then temporary not-found preserves intent against late container creation", () => {
  const f = fixture({ launch: () => { f.calls.push("launch"); return { status: null, error: "ETIMEDOUT" }; } });
  assert.throws(() => runWithDurablePgOwnerIntent(f.inputs), /reconciliation required/iu);
  assert.deepEqual(f.calls, ["create", "launch", "inspect"]);
  // The protected intent remains: a second late Docker creation must be
  // reconciled by the operator, not silently forgotten on transient ENOENT.
  assert.equal(f.calls.includes("clear"), false);
});

test("journal failure blocks Docker creation before any side effect", () => {
  const f = fixture({ journal: {
    create: () => { f.calls.push("create-refused"); throw Error("ACL unavailable"); },
    append: () => {}, clear: () => {},
  } });
  assert.throws(() => runWithDurablePgOwnerIntent(f.inputs));
  assert.deepEqual(f.calls, ["create-refused"]);
});

test("normal complete --rm return and independently absent owner clear evidence", () => {
  const f = fixture();
  assert.equal(runWithDurablePgOwnerIntent(f.inputs).status, 0);
  assert.deepEqual(f.calls, ["create", "launch", "inspect", "clear"]);
});

test("only explicit fixture pre-init URL rejection exit 97 is an acknowledged controlled refusal", () => {
  const expected = fixture({
    expectedExitCode: 97,
    launch: () => ({ status: 97, error: undefined }),
  });
  assert.equal(runWithDurablePgOwnerIntent(expected.inputs).status, 97);
  assert.deepEqual(expected.calls, ["create", "inspect", "clear"]);
  const unexpected = fixture({ launch: () => ({ status: 97, error: undefined }) });
  assert.throws(() => runWithDurablePgOwnerIntent(unexpected.inputs), /reconciliation required/iu);
  assert.equal(unexpected.calls.includes("clear"), false);
});

test("name/owner mismatch refuses rm and retains durable evidence", () => {
  const f = fixture({ inspect: () => { f.calls.push("inspect"); return {
    ...found, stdout: `${id}|/${name}|${"f".repeat(32)}`,
  }; } });
  assert.throws(() => runWithDurablePgOwnerIntent(f.inputs), /reconciliation required/iu);
  assert.deepEqual(f.calls, ["create", "launch", "inspect"]);
});

test("verified immutable ID removal plus post-removal absence is required before journal clear", () => {
  let probes = 0;
  const f = fixture({
    inspect: (target) => {
      f.calls.push(`inspect:${target}`);
      return probes++ === 0 ? found : missing;
    },
    remove: (target) => { assert.equal(target, id); f.calls.push(`remove:${target}`); return { status: 0 }; },
  });
  assert.equal(runWithDurablePgOwnerIntent(f.inputs).status, 0);
  assert.deepEqual(f.calls, ["create", "launch", `inspect:${name}`, "append", `remove:${id}`, `inspect:${id}`, "clear"]);
});

test("uncertain launch may clean only verified ID but must retain intent even after removal", () => {
  let probes = 0;
  const f = fixture({
    launch: () => { f.calls.push("launch-timeout"); return { error: "timeout", status: null }; },
    inspect: () => { f.calls.push("inspect"); return probes++ === 0 ? found : missing; },
  });
  assert.throws(() => runWithDurablePgOwnerIntent(f.inputs), /reconciliation required/iu);
  assert.equal(f.calls.includes("clear"), false);
});
