import { createHash } from "node:crypto";

export type CatalogVisibility = "PUBLIC" | "UNLISTED" | "PRIVATE";
export type RuntimeAvailability = "AVAILABLE" | "UNAVAILABLE" | "INERT";
export type AccessDurationKind = "PERMANENT" | "TEMPORARY";
export type AccessGrantStatus = "ACTIVE" | "EXPIRED" | "REVOKED";

export type InitialModuleCatalogEntry = {
  key: string;
  name: string;
  visibility: CatalogVisibility;
  runtimeAvailability: RuntimeAvailability;
  requestable: boolean;
  separateRepository: boolean;
};

export const MODULE_REQUEST_COOLDOWN_MS = 24 * 60 * 60 * 1000;

export const INITIAL_MODULE_CATALOG: readonly InitialModuleCatalogEntry[] = [
  {
    key: "gymforge",
    name: "GymForge",
    visibility: "PUBLIC",
    runtimeAvailability: "AVAILABLE",
    requestable: true,
    separateRepository: false
  },
  {
    key: "aip",
    name: "AIP",
    visibility: "PUBLIC",
    runtimeAvailability: "UNAVAILABLE",
    requestable: true,
    separateRepository: true
  },
  {
    key: "rootark",
    name: "root.ark",
    visibility: "PUBLIC",
    runtimeAvailability: "UNAVAILABLE",
    requestable: true,
    separateRepository: false
  },
  {
    key: "lvault",
    name: "L-vault",
    visibility: "PRIVATE",
    runtimeAvailability: "INERT",
    requestable: false,
    separateRepository: false
  },
  {
    key: "hvault",
    name: "H-vault",
    visibility: "PRIVATE",
    runtimeAvailability: "INERT",
    requestable: false,
    separateRepository: false
  }
];

type ModuleCatalogWriter = {
  moduleCatalog: {
    upsert(args: {
      where: { key: string };
      create: InitialModuleCatalogEntry;
      update: Omit<InitialModuleCatalogEntry, "key">;
    }): Promise<unknown>;
  };
};

export async function seedInitialModuleCatalog(client: ModuleCatalogWriter): Promise<void> {
  for (const entry of INITIAL_MODULE_CATALOG) {
    const { key, ...values } = entry;
    await client.moduleCatalog.upsert({
      where: { key },
      create: entry,
      update: values
    });
  }
}

export function normalizeIdentityEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function isPublicRequestableModule(
  module: Pick<InitialModuleCatalogEntry, "visibility" | "requestable">
): boolean {
  return module.visibility === "PUBLIC" && module.requestable;
}

export function getModuleRequestRetryAt(createdAt: Date): Date {
  return new Date(createdAt.getTime() + MODULE_REQUEST_COOLDOWN_MS);
}

export function canCreateRequest(
  lastCreatedAt: Date | null,
  now = new Date(),
  retryAfterAt: Date | null = null,
  indefinitelyBlocked = false
): boolean {
  if (indefinitelyBlocked || (retryAfterAt && retryAfterAt > now)) {
    return false;
  }

  return !lastCreatedAt || getModuleRequestRetryAt(lastCreatedAt) <= now;
}

export function isAccessGrantActive(
  grant: Pick<
    { status: AccessGrantStatus; accessDurationKind: AccessDurationKind; expiresAt: Date | null },
    "status" | "accessDurationKind" | "expiresAt"
  >,
  now = new Date()
): boolean {
  if (grant.status !== "ACTIVE") {
    return false;
  }

  return (
    grant.accessDurationKind === "PERMANENT" ||
    (grant.expiresAt !== null && grant.expiresAt > now)
  );
}

export function createRequestKey(
  userId: string,
  targetId: string,
  createdAt: Date
): string {
  return createHash("sha256")
    .update(`${userId}:${targetId}:${createdAt.toISOString()}`, "utf8")
    .digest("hex");
}

export function assertAccessDuration(
  accessDurationKind: AccessDurationKind,
  expiresAt: Date | null
): void {
  if (accessDurationKind === "TEMPORARY" && !expiresAt) {
    throw new Error("Temporary access requires an expiry.");
  }

  if (accessDurationKind === "PERMANENT" && expiresAt) {
    throw new Error("Permanent access cannot have an expiry.");
  }
}
