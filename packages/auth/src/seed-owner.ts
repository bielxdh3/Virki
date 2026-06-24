import { prisma } from "@bielos/database";
import { hashAuditEmail, hashPassword, normalizeEmail, writeAuditLog } from "./index";

const ownerEmail = process.env.BIELOS_OWNER_EMAIL;
const ownerPassword = process.env.BIELOS_OWNER_PASSWORD;

async function main() {
  if (!ownerEmail || !ownerPassword) {
    throw new Error("BIELOS_OWNER_EMAIL and BIELOS_OWNER_PASSWORD are required.");
  }

  if (ownerPassword.length < 12) {
    throw new Error("BIELOS_OWNER_PASSWORD must be at least 12 characters.");
  }

  const email = normalizeEmail(ownerEmail);
  const passwordHash = await hashPassword(ownerPassword);
  const existingOwner = await prisma.user.findUnique({
    where: { email },
    select: { id: true }
  });

  const owner = await prisma.user.upsert({
    where: { email },
    update: {
      passwordHash,
      role: "OWNER",
      isActive: true
    },
    create: {
      email,
      passwordHash,
      role: "OWNER",
      isActive: true
    }
  });

  await writeAuditLog({
    eventType: existingOwner ? "OWNER_SEED_UPDATED" : "OWNER_SEED_CREATED",
    result: "SUCCESS",
    actorUserId: owner.id,
    actorEmailHash: hashAuditEmail(email),
    resource: "owner-seed",
    message: existingOwner ? "OWNER seed updated." : "OWNER seed created.",
    metadata: {
      source: "seed-owner"
    }
  });

  console.log("OWNER user is ready.");
}

main()
  .catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
