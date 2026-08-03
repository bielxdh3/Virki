import assert from "node:assert/strict";
import { Readable } from "node:stream";
import { test } from "node:test";
import { createIntakeHandler, parseSubmission, type IntakeRepository } from "./handler";
import { createDatabaseIntakeRepository } from "./repository";

function request(method: string, url: string, body?: string, headers: Record<string, string> = {}) {
  const stream = Readable.from(body ? [body] : []);
  Object.assign(stream, { method, url, headers });
  return stream as never;
}

function response() {
  const headers = new Map<string, string>();
  let body = "";
  const output = {
    statusCode: 200,
    headersSent: false,
    setHeader(name: string, value: string) {
      headers.set(name, value);
    },
    end(value?: string) {
      output.headersSent = true;
      body = value ?? "";
    }
  };
  return { output: output as never, headers, getBody: () => JSON.parse(body) };
}

test("rejects malformed, wrong-origin, and wrong-content-type intake requests", async () => {
  const repository: IntakeRepository = {
    async listPublicModules() { return []; },
    async submitApplication() { throw new Error("not expected"); },
    async verifyApplicationEmail() { throw new Error("not expected"); },
    async activateApplication() { throw new Error("not expected"); }
  };
  const handler = createIntakeHandler(repository, {
    enabled: true,
    publicOrigin: "https://biel.dev.br",
    abuseSecret: "test-abuse-secret"
  });

  const wrongOrigin = response();
  await handler(
    request("POST", "/api/apply", "{}", {
      origin: "https://evil.example",
      "content-type": "application/json"
    }),
    wrongOrigin.output
  );
  assert.equal((wrongOrigin.output as { statusCode: number }).statusCode, 403);

  const wrongType = response();
  await handler(
    request("POST", "/api/apply", "{}", {
      origin: "https://biel.dev.br",
      "content-type": "text/plain"
    }),
    wrongType.output
  );
  assert.equal((wrongType.output as { statusCode: number }).statusCode, 415);
});

test("accepts bounded valid submissions and stores only an HMAC abuse identifier", () => {
  const submission = parseSubmission(
    {
      email: " Applicant@Example.COM ",
      displayName: "Applicant",
      locale: "en",
      modules: [{ key: "gymforge", reason: "Need access for a private training workflow." }]
    },
    "test-abuse-secret"
  );
  assert.equal(submission?.emailNormalized, "applicant@example.com");
  assert.equal(submission?.locale, "en");
  assert.match(submission?.abuseIdentifierHash ?? "", /^[a-f0-9]{64}$/);
  assert.equal(submission?.abuseIdentifierHash?.includes("applicant"), false);
});

test("public catalog path serializes only allowlisted module fields", async () => {
  const repository = createDatabaseIntakeRepository(
    {
      async $queryRaw() {
        return [
          {
            id: "internal-module-id",
            key: "gymforge",
            name: "GymForge",
            runtimeAvailability: "AVAILABLE"
          }
        ];
      }
    } as never,
    "https://biel.dev.br"
  );
  const output = response();

  await createIntakeHandler(repository, {
    enabled: true,
    publicOrigin: "https://biel.dev.br",
    abuseSecret: "test-abuse-secret"
  })(request("GET", "/api/catalog"), output.output);

  const body = output.getBody() as {
    available: boolean;
    modules: Array<Record<string, unknown>>;
  };
  assert.equal(body.available, true);
  assert.deepEqual(body.modules, [
    { key: "gymforge", name: "GymForge", runtimeAvailability: "AVAILABLE" }
  ]);
  assert.equal(JSON.stringify(body).includes("internal-module-id"), false);
});

test("disabled or misconfigured intake remains fail-closed", async () => {
  let repositoryCalled = false;
  const repository: IntakeRepository = {
    async listPublicModules() {
      repositoryCalled = true;
      return [];
    },
    async submitApplication() {
      repositoryCalled = true;
    },
    async verifyApplicationEmail() {
      repositoryCalled = true;
    },
    async activateApplication() {
      repositoryCalled = true;
    }
  };

  const disabled = response();
  await createIntakeHandler(repository, {
    enabled: false,
    publicOrigin: "https://biel.dev.br",
    abuseSecret: "test-abuse-secret"
  })(request("GET", "/api/catalog"), disabled.output);
  assert.equal((disabled.output as { statusCode: number }).statusCode, 503);

  const misconfigured = response();
  await createIntakeHandler(repository, {
    enabled: true,
    publicOrigin: "https://biel.dev.br",
    abuseSecret: null
  })(
    request("POST", "/api/apply", "{}", {
      origin: "https://biel.dev.br",
      "content-type": "application/json"
    }),
    misconfigured.output
  );
  assert.equal((misconfigured.output as { statusCode: number }).statusCode, 503);
  assert.equal(repositoryCalled, false);
});
