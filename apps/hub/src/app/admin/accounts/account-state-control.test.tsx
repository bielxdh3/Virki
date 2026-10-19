import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { AccountStateRow } from "./account-state-control";
import { accountStateTransitionWhere } from "./account-state-policy";

type ElementWithChildren = React.ReactElement<{ children?: React.ReactNode; name?: string; value?: string }>;

function flatten(node: React.ReactNode): ElementWithChildren[] {
  if (Array.isArray(node)) return node.flatMap(flatten);
  if (!React.isValidElement(node)) return [];
  const element = node as ElementWithChildren;
  return [element, ...flatten(element.props.children)];
}

function collectText(node: React.ReactNode): string {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(collectText).join(" ");
  if (!React.isValidElement(node)) return "";
  return collectText((node as ElementWithChildren).props.children);
}

function renderState(user: { isActive: boolean; accountStatus: "PENDING_ACTIVATION" | "ACTIVE" | "BLOCKED" | "INACTIVE" }) {
  return AccountStateRow({
    csrf: "test-csrf",
    user: { id: "user-12345678", email: "person@example.test", displayName: null, secondFactorMethod: "EMAIL", projectGrantCount: 0, ...user }
  });
}

test("admin account rows show accountStatus and offer actions only for consistent active or inactive states", () => {
  const expected = [
    { isActive: true, accountStatus: "ACTIVE" as const, label: "Ativa", action: "Suspender", enabled: "false" },
    { isActive: false, accountStatus: "INACTIVE" as const, label: "Suspensa", action: "Reativar", enabled: "true" },
    { isActive: true, accountStatus: "BLOCKED" as const, label: "Bloqueada", action: null, enabled: null },
    { isActive: false, accountStatus: "PENDING_ACTIVATION" as const, label: "Pendente de ativação", action: null, enabled: null },
    { isActive: false, accountStatus: "ACTIVE" as const, label: "inconsistente", action: null, enabled: null },
    { isActive: true, accountStatus: "INACTIVE" as const, label: "inconsistente", action: null, enabled: null }
  ];

  for (const state of expected) {
    const row = renderState(state);
    const elements = flatten(row);
    const forms = elements.filter((element) => element.type === "form");
    const text = collectText(row);
    assert.match(text, new RegExp(state.label, "iu"), `${state.accountStatus} is displayed accurately`);
    assert.equal(forms.length, state.action ? 1 : 0, `${state.accountStatus}/${state.isActive} only exposes a supported transition`);
    if (state.action) {
      assert.match(text, new RegExp(state.action, "u"));
      const enabled = elements.find((element) => element.type === "input" && element.props.name === "enabled");
      assert.equal(enabled?.props.value, state.enabled);
    }
  }
});

test("account state mutations match the expected current flag and canonical status", () => {
  assert.deepEqual(accountStateTransitionWhere("user-12345678", false), {
    id: "user-12345678", role: "USER", isActive: true, accountStatus: "ACTIVE"
  });
  assert.deepEqual(accountStateTransitionWhere("user-12345678", true), {
    id: "user-12345678", role: "USER", isActive: false, accountStatus: "INACTIVE"
  });
});
