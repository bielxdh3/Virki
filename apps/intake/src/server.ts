import { createServer } from "node:http";
import { createRestrictedIntakeClient } from "@bielos/database";
import { getEmailTransportStatus } from "@bielos/auth/email";
import { createIntakeHandler, type IntakeConfig } from "./handler";
import { createDatabaseIntakeRepository } from "./repository";

const port = Number(process.env.INTAKE_PORT ?? 3002);
const publicOrigin = process.env.PUBLIC_SITE_ORIGIN ?? "https://biel.dev.br";
const client = createRestrictedIntakeClient();
const emailConfigured = getEmailTransportStatus().state === "configured";
const config: IntakeConfig = {
  enabled: process.env.BIELOS_INTAKE_ENABLED === "true" && client !== null && emailConfigured,
  publicOrigin,
  abuseSecret: process.env.BIELOS_INTAKE_ABUSE_SECRET?.trim() || null
};

const repository = client
  ? createDatabaseIntakeRepository(client, publicOrigin)
  : {
      async listPublicModules() {
        return [];
      },
      async submitApplication() {
        throw new Error("Intake database is unavailable.");
      },
      async verifyApplicationEmail() {
        throw new Error("Intake database is unavailable.");
      },
      async activateApplication() {
        throw new Error("Intake database is unavailable.");
      }
    };

const server = createServer((request, response) => {
  void createIntakeHandler(repository, config)(request, response).catch(() => {
    if (!response.headersSent) {
      response.statusCode = 503;
      response.setHeader("Content-Type", "application/json; charset=utf-8");
    }
    response.end(JSON.stringify({ accepted: false, available: false }));
  });
});

server.listen(port, "0.0.0.0", () => {
  // This service is intentionally quiet about configuration and database state.
});

const shutdown = () => {
  void client?.$disconnect().finally(() => server.close());
};

process.once("SIGTERM", shutdown);
process.once("SIGINT", shutdown);
