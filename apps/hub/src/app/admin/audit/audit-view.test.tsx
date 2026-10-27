import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { parseAuditFilters } from "@virki/auth/audit-query";
import { AuditView } from "./audit-view";
import AuditLayout from "./layout";
import AuditLoading from "./loading";

test("audit keeps one stable focus target around loading and settled route content", () => {
  (globalThis as typeof globalThis & { React: typeof React }).React = React;
  const loading = renderToStaticMarkup(<AuditLayout><AuditLoading /></AuditLayout>);
  const settled = renderToStaticMarkup(<AuditLayout><AuditView filters={parseAuditFilters({})} rows={[]} hasNext={false} /></AuditLayout>);
  for (const html of [loading, settled]) {
    assert.equal((html.match(/<main\b/gu) ?? []).length, 1);
    assert.match(html, /<main class="admin-main" id="admin-content" tabindex="-1">/u);
    assert.match(html, /<h1>Auditoria<\/h1>/u);
  }
});

test("audit investigation renders safe references and collapsed details without raw legacy payloads", () => {
  (globalThis as typeof globalThis & { React: typeof React }).React = React;
  const html = renderToStaticMarkup(<AuditView filters={parseAuditFilters({ q: "AUTH" })} hasNext rows={[{
    id: "event-12345678", eventType: "AUTH_LOGIN_FAILURE", result: "FAILURE", resource: "hub", createdAt: new Date("2026-01-01T02:03:00Z"), actorUserId: "actor-123", actorEmailHash: null, actorRef: null, actorRole: null, category: "AUTH", severity: "WARNING", action: "auth.login.failure", reason: "rejected", schemaVersion: 1, requestId: null, sessionRef: null, deviceRef: null, targetRef: null, service: null, route: null, method: null, networkProvenance: "unavailable", beforeState: null, afterState: null,
    metadata: { source: "hub-login", private: "private@example.invalid", password: "synthetic-secret" }
  }]} />);
  assert.doesNotMatch(html, /private@example|synthetic-secret|<details open/u);
  assert.match(html, /31\/12\/2025, 22:03/u);
  assert.match(html, /America\/Porto_Velho/u);
  assert.match(html, /Conta [a-f0-9]{12}/u);
  assert.match(html, /name="q"/u);
  assert.match(html, /Próxima página/u);
  assert.match(html, /Detalhes seguros/u);
});
