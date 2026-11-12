import assert from "node:assert/strict";
import test from "node:test";
import type { prisma } from "@virki/database";
import { assertScopedEmailWorkerRole, requireScopedEmailWorkerRole } from "./email-worker-role";

test("only the explicit staging role requirement enables fail-closed verification", () => {
  assert.equal(requireScopedEmailWorkerRole(undefined), false);
  assert.equal(requireScopedEmailWorkerRole(""), false);
  assert.equal(requireScopedEmailWorkerRole("required"), true);
  for (const value of ["false", "true", "0", "required ", "disabled"]) {
    assert.throws(() => requireScopedEmailWorkerRole(value), /Invalid email worker role verification setting/u);
  }
});

test("scoped email worker guard requires exactly one explicit positive SQL privilege result", async () => {
  let queries = 0;
  const querySource: string[] = [];
  const database = {
    $queryRaw: async (strings: TemplateStringsArray) => {
      queries += 1;
      querySource.push(strings.join(""));
      return [{ allowed: true }];
    }
  } as unknown as typeof prisma;
  await assertScopedEmailWorkerRole(database);
  assert.equal(queries, 1);
  assert.match(querySource[0], /session_user = 'virki_email_worker'/u);
  assert.match(querySource[0], /pg_auth_members/u);
  assert.match(querySource[0], /has_column_privilege/u);
  assert.match(querySource[0], /has_function_privilege/u);
  assert.match(querySource[0], /has_schema_privilege/u);

  for (const result of [[], [{ allowed: false }], [{ allowed: null }], [{ allowed: true }, { allowed: true }]]) {
    const failing = { $queryRaw: async () => result } as unknown as typeof prisma;
    await assert.rejects(assertScopedEmailWorkerRole(failing), /not scoped for staging/u);
  }
  const connectionFailure = { $queryRaw: async () => { throw Error("DB unavailable"); } } as unknown as typeof prisma;
  await assert.rejects(assertScopedEmailWorkerRole(connectionFailure), /DB unavailable/u);
});
