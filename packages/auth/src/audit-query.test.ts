import assert from "node:assert/strict";
import test from "node:test";
import { parseAuditFilters, buildAuditQuery, auditPageHref } from "./audit-query";

test("search is limited to safe structured fields and bounded deterministic paging", () => {
  const filters = parseAuditFilters({ q: "account", result: "FAILURE", category: "ACCOUNT", actor: "system", sort: "oldest", page: "2" });
  const query = buildAuditQuery(filters);
  assert.deepEqual(query.orderBy, [{ createdAt: "asc" }, { id: "asc" }]);
  assert.equal(query.skip, 50);
  assert.equal(query.take, 51);
  assert.doesNotMatch(JSON.stringify(query), /"email"|"message"|"metadata"|\$queryRaw/iu);
  assert.match(JSON.stringify(query), /actorRef/u);
  assert.equal(query.where.result, "FAILURE");
});

test("ambiguous, excessive, secret-shaped and invalid date input fails closed", () => {
  for (const params of [{ q: ["a", "b"] }, { page: "1001" }, { q: "user@example.invalid" }, { q: "token=private" }, { from: "2026-02-30" }, { from: "2026-01-01", to: "2027-01-02" }, { from: "2026-10-01", to: "2026-09-01" }, { sort: "sql" }]) {
    assert.throws(() => parseAuditFilters(params));
  }
});

test("date boundaries use UTC minus four and safe URLs preserve combined filters", () => {
  const filters = parseAuditFilters({ q: "AUTH_LOGIN", from: "2026-01-01", to: "2026-01-02", result: "SUCCESS" });
  const query = buildAuditQuery(filters);
  assert.deepEqual(query.where.createdAt, { gte: new Date("2026-01-01T04:00:00Z"), lt: new Date("2026-01-03T04:00:00Z") });
  assert.match(auditPageHref(filters, 2), /q=AUTH_LOGIN/u);
  assert.match(auditPageHref(filters, 2), /result=SUCCESS/u);
  assert.match(auditPageHref(filters, 2), /page=2/u);
});

test("underscore in event prefix is literal rather than a LIKE wildcard", () => {
  const query = buildAuditQuery(parseAuditFilters({ q: "AUTH_LOGIN" }));
  assert.match(JSON.stringify(query), /AUTH\\\\_LOGIN/u);
});

test("exact event ID accepts safe dotted identifiers used by persisted events", () => {
  const query = buildAuditQuery(parseAuditFilters({ id: "browser.03ea2af7-000" }));
  assert.equal(query.where.id, "browser.03ea2af7-000");
});
