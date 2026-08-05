import { prisma } from "@bielos/database";
import { createSmtpEmailTransport, getEmailTransportStatus, processNextEmailMessage } from "./email";
import { runAuthCommand } from "./command-output";

const EMAIL_WORKER_POLL_INTERVAL_MS = 5_000;

let shuttingDown = false;
let wakePoll: (() => void) | null = null;

function requestShutdown() {
  shuttingDown = true;
  wakePoll?.();
}

function waitForNextPoll(): Promise<void> {
  if (shuttingDown) {
    return Promise.resolve();
  }

  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      wakePoll = null;
      resolve();
    }, EMAIL_WORKER_POLL_INTERVAL_MS);

    wakePoll = () => {
      clearTimeout(timer);
      wakePoll = null;
      resolve();
    };
  });
}

async function main() {
  if (getEmailTransportStatus().state !== "configured") {
    throw new Error("Email worker configuration is unavailable.");
  }

  const transport = createSmtpEmailTransport();
  while (!shuttingDown) {
    await processNextEmailMessage(transport);
    await waitForNextPoll();
  }
}

process.once("SIGTERM", requestShutdown);
process.once("SIGINT", requestShutdown);

void runAuthCommand("email-worker", main, () => prisma.$disconnect());
