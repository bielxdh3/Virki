import { requireSecurityElevation } from "@bielos/auth/administration";
import type { CoreProjectPrincipal } from "../authorization";
import {
  isCoreProjectAccessLevel,
  type CoreProjectAccessLevel
} from "./access-policy";
import {
  isValidCoreResourceId
} from "./validation";
import { setCoreProjectAccessRecord } from "./access-service";

export const CORE_PROJECT_ACCESS_ELEVATION_SCOPE = "PROJECT_OWNER_ACCESS_CHANGE" as const;

export type CoreProjectAccessForm = {
  projectId: string;
  userId: string;
  accessLevel: CoreProjectAccessLevel;
};

export class CoreProjectAccessActionError extends Error {
  constructor(public readonly stage: "input" | "elevation" | "mutation") {
    super("Core project access action rejected.");
    this.name = "CoreProjectAccessActionError";
  }
}

export function readCoreProjectAccessForm(formData: FormData): CoreProjectAccessForm | null {
  const projectId = readFormString(formData, "projectId");
  const userId = readFormString(formData, "userId");
  const accessLevel = readFormString(formData, "accessLevel");

  if (
    !isValidCoreResourceId(projectId) ||
    !isValidCoreResourceId(userId) ||
    !isCoreProjectAccessLevel(accessLevel)
  ) {
    return null;
  }

  return { projectId, userId, accessLevel };
}

export async function executeCoreProjectAccessAction(
  formData: FormData,
  actor: CoreProjectPrincipal,
  sessionId: string,
  dependencies: {
    requireElevation?: (userId: string, sessionId: string) => Promise<void>;
    setAccess?: typeof setCoreProjectAccessRecord;
  } = {}
) {
  const input = readCoreProjectAccessForm(formData);

  if (!input) {
    throw new CoreProjectAccessActionError("input");
  }

  // Global OWNER authority covers routine project participant/access changes.
  // ADMIN keeps the existing elevation ceremony for non-owner access changes.
  if (actor.role !== "OWNER") {
    try {
      await (dependencies.requireElevation ?? (async (userId, currentSessionId) =>
        requireSecurityElevation(userId, currentSessionId, CORE_PROJECT_ACCESS_ELEVATION_SCOPE)
      ))(actor.id, sessionId);
    } catch {
      throw new CoreProjectAccessActionError("elevation");
    }
  }

  try {
    const result = await (dependencies.setAccess ?? setCoreProjectAccessRecord)(
      actor,
      input.projectId,
      input.userId,
      input.accessLevel
    );

    return { input, result };
  } catch {
    throw new CoreProjectAccessActionError("mutation");
  }
}

function readFormString(formData: FormData, key: string): string {
  const value = formData.get(key);
  return typeof value === "string" ? value.trim() : "";
}
