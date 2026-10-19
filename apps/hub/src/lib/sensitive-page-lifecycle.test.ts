import assert from "node:assert/strict";
import test from "node:test";
import { registerProtectedPageLifecycle, registerSensitivePageScrub, scrubSensitivePageSnapshot } from "./sensitive-page-lifecycle";

test("protected page content is scrubbed on hide without reloading an ordinary pageshow", () => {
  const target = new EventTarget() as unknown as Window;
  const events: string[] = [];
  const unregister = registerProtectedPageLifecycle(
    target,
    () => events.push("scrub"),
    () => events.push("reload"),
    () => false,
  );

  target.dispatchEvent(new Event("pageshow"));
  assert.deepEqual(events, []);

  target.dispatchEvent(new Event("pagehide"));
  assert.deepEqual(events, ["scrub"]);

  target.dispatchEvent(new Event("pageshow"));
  assert.deepEqual(events, ["scrub"]);

  unregister();
  target.dispatchEvent(new Event("pagehide"));
  assert.deepEqual(events, ["scrub"]);
});

test("protected page reloads when a history traversal is detected during hydration", () => {
  const target = new EventTarget() as unknown as Window;
  const events: string[] = [];
  const unregister = registerProtectedPageLifecycle(
    target,
    () => events.push("scrub"),
    () => events.push("reload"),
    () => true,
  );

  assert.deepEqual(events, ["scrub", "reload"]);
  target.dispatchEvent(new Event("pageshow"));
  assert.deepEqual(events, ["scrub", "reload"]);
  unregister();
});

test("protected page reloads when pageshow confirms a non-persisted history traversal", () => {
  const target = new EventTarget() as unknown as Window;
  const events: string[] = [];
  let historyTraversal = false;
  const unregister = registerProtectedPageLifecycle(
    target,
    () => events.push("scrub"),
    () => events.push("reload"),
    () => historyTraversal,
  );

  historyTraversal = true;
  target.dispatchEvent(new Event("pageshow"));
  assert.deepEqual(events, ["scrub", "reload"]);
  unregister();
});

test("protected page reloads when restored from the back-forward cache", () => {
  const target = new EventTarget() as unknown as Window;
  const events: string[] = [];
  const unregister = registerProtectedPageLifecycle(
    target,
    () => events.push("scrub"),
    () => events.push("reload"),
  );
  const restored = new Event("pageshow");
  Object.defineProperty(restored, "persisted", { value: true });

  target.dispatchEvent(restored);
  assert.deepEqual(events, ["scrub", "reload"]);
  unregister();
});

test("sensitive UI state is scrubbed on pagehide and persisted pageshow", () => {
  const target = new EventTarget() as unknown as Window;
  let recoveryCodes: string[] | undefined = ["one-time-code"];
  let scrubs = 0;
  const unregister = registerSensitivePageScrub(target, () => {
    recoveryCodes = undefined;
    scrubs += 1;
  });

  target.dispatchEvent(new Event("pagehide"));
  assert.equal(recoveryCodes, undefined);
  assert.equal(scrubs, 1);

  recoveryCodes = ["restored-one-time-code"];
  const restored = new Event("pageshow");
  Object.defineProperty(restored, "persisted", { value: true });
  target.dispatchEvent(restored);
  assert.equal(recoveryCodes, undefined);
  assert.equal(scrubs, 2);

  recoveryCodes = ["ordinary-pageshow-code"];
  target.dispatchEvent(new Event("pageshow"));
  assert.deepEqual(recoveryCodes, ["ordinary-pageshow-code"]);

  unregister();
  target.dispatchEvent(new Event("pagehide"));
  assert.deepEqual(recoveryCodes, ["ordinary-pageshow-code"]);
  assert.equal(scrubs, 2);
});

test("sensitive page scrub clears one-time DOM nodes and application state", () => {
  let recoveryCodes: string[] | undefined = ["one-time-code"];
  const visibleValues = ["one-time-code"];
  scrubSensitivePageSnapshot(
    () => { recoveryCodes = undefined; },
    [{ replaceChildren: () => visibleValues.splice(0) }],
  );

  assert.deepEqual(visibleValues, []);
  assert.equal(recoveryCodes, undefined);
});
