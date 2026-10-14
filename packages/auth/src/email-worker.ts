import { prisma } from "@virki/database";
import { createSmtpEmailTransport, getEmailTransportStatus, processNextEmailMessage } from "./email";
import { runAuthCommand } from "./command-output";
import { parseEmailSendIntervalMs, runEmailWorkerLoop } from "./email-worker-loop";

let shuttingDown = false;
let wakeSleep: (() => void) | null = null;

function requestShutdown() {
  shuttingDown = true;
  wakeSleep?.();
}

function sleep(milliseconds: number): Promise<void> {
  if (shuttingDown) {
    return Promise.resolve();
  }

  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      wakeSleep = null;
      resolve();
    }, milliseconds);

    wakeSleep = () => {
      clearTimeout(timer);
      wakeSleep = null;
      resolve();
    };
  });
}

async function main() {
  if (getEmailTransportStatus().state !== "configured") {
    throw new Error("Email worker configuration is unavailable.");
  }

  const transport = createSmtpEmailTransport();
  await runEmailWorkerLoop({
    processNext: () => processNextEmailMessage(transport),
    sleep,
    isStopping: () => shuttingDown,
    sendIntervalMs: parseEmailSendIntervalMs(process.env.VIRKI_EMAIL_MIN_SEND_INTERVAL_MS),
    onIterationError: () => {
      console.error("Email worker iteration failed; retrying after a pause.");
    }
  });
}

process.once("SIGTERM", requestShutdown);
process.once("SIGINT", requestShutdown);

void runAuthCommand("email-worker", main, () => prisma.$disconnect());
