import { PrismaClient, prisma } from "@virki/database";
import type { Prisma as PrismaTypes } from "@virki/database";
import { hashAuditEmail, writeAuditLogInTransaction } from "./audit";
import { hashPassword, normalizeEmail } from "./index";

async function countApplicationRows(transaction: PrismaTypes.TransactionClient): Promise<number[]> {
  return Promise.all([
    transaction.user.count(),
    transaction.session.count(),
    transaction.loginRateLimit.count(),
    transaction.projectConnection.count(),
    transaction.userProjectGrant.count(),
    transaction.oidcArtifact.count(),
    transaction.auditLog.count(),
    transaction.emailOutboxMessage.count(),
    transaction.emailDeliveryAttempt.count(),
    transaction.totpFactor.count(),
    transaction.recoveryCode.count(),
    transaction.deviceChallenge.count(),
    transaction.trustedDevice.count(),
    transaction.accountRecoveryRequest.count(),
    transaction.sanitizedAuditReference.count(),
    transaction.administrativeCredential.count(),
    transaction.administrativeRecoveryCode.count(),
    transaction.securityElevation.count()
  ]);
}

const BOOTSTRAP_LOCK_ID = 4_852_716_032_158_417_203n;

export class FirstAdminBootstrapError extends Error {
  constructor(readonly code: "INPUT_INVALID" | "DATABASE_NOT_VIRGIN" | "INTERACTIVE_TTY_REQUIRED" | "PRODUCTION_CONTEXT_REQUIRED" | "DATABASE_TARGET_INVALID" | "FIRST_INSTALL_NOT_ENABLED") {
    super(code);
    this.name = "FirstAdminBootstrapError";
  }
}

type BootstrapInput = {
  email: string;
  displayName?: string;
  password: string;
};

type BootstrapDependencies = {
  database?: Pick<PrismaClient, "$transaction">;
  hashPassword?: (password: string) => Promise<string>;
  hashAdminEmail?: (email: string) => string;
  writeAudit?: typeof writeAuditLogInTransaction;
  now?: Date;
};

export async function bootstrapFirstAdmin(input: BootstrapInput, dependencies: BootstrapDependencies = {}): Promise<{ id: string }> {
  const email = normalizeEmail(input.email);
  const displayName = input.displayName?.trim() || "";
  if (!/^\S+@\S+\.\S+$/u.test(email) || email.length > 320 || input.password.length < 16 || input.password.length > 256 || containsControlCharacter(input.password) || displayName.length > 80 || containsControlCharacter(displayName)) {
    throw new FirstAdminBootstrapError("INPUT_INVALID");
  }

  const database = dependencies.database ?? prisma;
  const hash = dependencies.hashPassword ?? hashPassword;
  const hashEmail = dependencies.hashAdminEmail ?? hashAuditEmail;
  const writeAudit = dependencies.writeAudit ?? writeAuditLogInTransaction;
  const now = dependencies.now ?? new Date();

  return database.$transaction(async (transaction) => {
    await transaction.$queryRaw`SELECT pg_advisory_xact_lock(${BOOTSTRAP_LOCK_ID})`;
    const counts = await countApplicationRows(transaction);
    if (counts.some((count) => count !== 0)) throw new FirstAdminBootstrapError("DATABASE_NOT_VIRGIN");

    const passwordHash = await hash(input.password);
    const user = await transaction.user.create({
      data: {
        email,
        emailNormalized: email,
        displayName: displayName || null,
        passwordHash,
        role: "ADMIN",
        isActive: true,
        accountStatus: "ACTIVE",
        emailVerifiedAt: null,
        secondFactorMethod: "EMAIL",
        createdAt: now
      },
      select: { id: true }
    });
    await writeAudit(transaction, {
      eventType: "ACCOUNT_CREATED",
      result: "SUCCESS",
      actorUserId: user.id,
      actorEmailHash: hashEmail(email),
      resource: "identity.admin",
      message: "Initial ADMIN account provisioned through restricted operator bootstrap."
    });
    return user;
  }, { isolationLevel: "Serializable" });
}

function containsControlCharacter(value: string): boolean {
  return Array.from(value).some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint < 0x20 || codePoint === 0x7f;
  });
}

export function assertProductionBootstrapContext(env: NodeJS.ProcessEnv): void {
  if (env.VIRKI_FIRST_INSTALL_BOOTSTRAP !== "enabled") throw new FirstAdminBootstrapError("FIRST_INSTALL_NOT_ENABLED");
  if (env.NODE_ENV !== "production") throw new FirstAdminBootstrapError("PRODUCTION_CONTEXT_REQUIRED");
  try {
    const url = new URL(env.DATABASE_URL ?? "");
    if (url.protocol !== "postgresql:" || url.hostname !== "postgres" || (url.port !== "" && url.port !== "5432") || decodeURIComponent(url.username) !== "virki_runtime" || url.pathname !== "/virki" || (url.searchParams.has("schema") && url.searchParams.get("schema") !== "public")) {
      throw new Error("invalid database target");
    }
  } catch {
    throw new FirstAdminBootstrapError("DATABASE_TARGET_INVALID");
  }
  if (!/^[a-f0-9]{64}$/iu.test(env.VIRKI_AUDIT_HASH_SECRET ?? "")) {
    throw new FirstAdminBootstrapError("PRODUCTION_CONTEXT_REQUIRED");
  }
}

async function readTerminalLine(label: string, secret = false, maxLength = 320): Promise<string> {
  const input = process.stdin;
  if (!input.isTTY || typeof input.setRawMode !== "function" || !process.stdout.isTTY) {
    throw new FirstAdminBootstrapError("INTERACTIVE_TTY_REQUIRED");
  }

  process.stdout.write(label);
  input.setEncoding("utf8");
  input.setRawMode(true);
  input.resume();
  return new Promise((resolve, reject) => {
    let value = "";
    const finish = (error?: Error) => {
      input.off("data", onData);
      input.off("error", onError);
      input.setRawMode(false);
      input.pause();
      process.stdout.write("\n");
      if (error) reject(error);
      else resolve(value);
    };
    const onError = (error: Error) => finish(error);
    const onData = (chunk: string) => {
      for (const character of chunk) {
        if (character === "\u0003") {
          finish(new Error("cancelled"));
          return;
        }
        if (character === "\r" || character === "\n") {
          finish();
          return;
        }
        if (character === "\u007f" || character === "\b") {
          if (value.length > 0) {
            value = Array.from(value).slice(0, -1).join("");
            if (!secret) process.stdout.write("\b \b");
          }
          continue;
        }
        if (/^[\u0020-\u007e]$/u.test(character)) {
          value += character;
          if (!secret) process.stdout.write(character);
        } else if (!containsControlCharacter(character)) {
          value += character;
          if (!secret) process.stdout.write(character);
        }
        if (Array.from(value).length > maxLength) {
          finish(new Error("input too long"));
          return;
        }
      }
    };
    input.on("data", onData);
    input.once("error", onError);
  });
}

async function runInteractiveBootstrap(): Promise<void> {
  assertProductionBootstrapContext(process.env);
  const email = await readTerminalLine("Initial ADMIN email: ", false, 320);
  const displayName = await readTerminalLine("Display name (optional): ", false, 80);
  const password = await readTerminalLine("Initial ADMIN password (16+ characters): ", true, 256);
  const confirmation = await readTerminalLine("Confirm password: ", true, 256);
  if (password !== confirmation) {
    throw new FirstAdminBootstrapError("INPUT_INVALID");
  }
  await bootstrapFirstAdmin({ email, displayName, password });
  console.log("Initial ADMIN account created. Complete email verification during the first sign-in.");
}

if (process.argv[1] && process.argv[1].replaceAll("\\", "/").endsWith("/bootstrap-first-admin.ts")) {
  runInteractiveBootstrap()
  .catch((error) => {
      const message = error instanceof FirstAdminBootstrapError
        ? error.code === "DATABASE_NOT_VIRGIN"
          ? "First ADMIN bootstrap refused because application data already exists."
          : error.code === "INTERACTIVE_TTY_REQUIRED"
            ? "First ADMIN bootstrap requires an interactive protected terminal."
          : error.code === "FIRST_INSTALL_NOT_ENABLED"
            ? "First ADMIN bootstrap requires the explicit first-install operation."
            : error.code === "DATABASE_TARGET_INVALID"
              ? "First ADMIN bootstrap refused because the database target is not the isolated Virki database."
              : error.code === "PRODUCTION_CONTEXT_REQUIRED"
                ? "First ADMIN bootstrap requires the protected Virki production runtime."
                : "First ADMIN bootstrap input is invalid."
        : "First ADMIN bootstrap failed; no credential details are available in this output.";
      console.error(message);
      process.exitCode = 1;
    })
    .finally(async () => {
      await prisma.$disconnect();
    });
}
