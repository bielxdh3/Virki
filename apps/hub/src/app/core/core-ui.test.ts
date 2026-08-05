import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import test from "node:test";
import { CoreShell, getCoreShellClassName } from "./shell";
import { getCoreNavigationItems } from "./navigation";
import { getTrustedDeviceCopy, getTrustedDeviceDisplay } from "./security/trusted-device-view";

test("Core shell renders an explicit docked or standalone contract", () => {
  const docked = renderToStaticMarkup(createElement(CoreShell, {
    variant: "docked",
    locale: "en",
    role: "MEMBER",
    children: createElement("p", null, "content")
  }));
  const standalone = renderToStaticMarkup(createElement(CoreShell, {
    variant: "standalone",
    locale: "en",
    role: "MEMBER",
    children: createElement("p", null, "content")
  }));

  assert.match(docked, /hub-shell--docked/);
  assert.match(docked, /os-dock/);
  assert.match(docked, /hub-workspace/);
  assert.match(standalone, /hub-shell--standalone/);
  assert.doesNotMatch(standalone, /os-dock/);
  assert.match(standalone, /hub-workspace/);
  assert.match(getCoreShellClassName("standalone"), /hub-shell--standalone/);
  assert.doesNotMatch(getCoreShellClassName("standalone"), /hub-shell--docked/);
});

test("Core navigation is localized, fixed, and role-aware", () => {
  const member = getCoreNavigationItems("pt-BR", "MEMBER");
  const owner = getCoreNavigationItems("en", "OWNER");

  assert.deepEqual(member.map((item) => item.href), [
    "/",
    "/core/projects",
    "/core/security",
    "/core/security/account",
    "/core/modules"
  ]);
  assert.deepEqual(owner.map((item) => item.href), [
    "/",
    "/core/projects",
    "/core/security",
    "/core/security/account",
    "/core/modules",
    "/core/security/admin",
    "/core/applications"
  ]);
  assert.equal(member.some((item) => item.href === "/core/security/admin"), false);
  assert.equal(member.some((item) => item.href === "/core/applications"), false);
  assert.equal(owner.find((item) => item.href === "/core/security/admin")?.label, "Administrative security");
  assert.equal(member.find((item) => item.href === "/core/security/admin"), undefined);
  assert.equal(member.find((item) => item.href === "/core/security/account")?.label, "Segurança da conta");
  assert.ok([...member, ...owner].every((item) => item.href.startsWith("/")));
});

test("trusted-device copy and display omit device identifiers", () => {
  const pt = getTrustedDeviceCopy("pt-BR");
  const en = getTrustedDeviceCopy("en");
  const deviceKey = "opaque-device-key-value";
  const display = getTrustedDeviceDisplay({
    label: null,
    lastSeenAt: new Date("2026-08-05T12:00:00.000Z"),
    createdAt: new Date("2026-08-01T12:00:00.000Z")
  }, "en");

  assert.equal(pt.empty, "Nenhum dispositivo confiável está registrado.");
  assert.equal(en.empty, "No trusted devices are registered.");
  assert.equal(display.label, en.defaultLabel);
  assert.match(display.lastSeen, /2026/);
  assert.match(display.created, /2026/);
  assert.equal("deviceKey" in display, false);
  assert.equal(JSON.stringify(display).includes(deviceKey), false);
});
