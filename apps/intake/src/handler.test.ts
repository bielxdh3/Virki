import assert from "node:assert/strict";
import { Readable } from "node:stream";
import { test } from "node:test";
import { createIntakeHandler, parseSubmission, type IntakeRepository } from "./handler";

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
    async submitApplication() { throw new Error("not expected"); }
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
