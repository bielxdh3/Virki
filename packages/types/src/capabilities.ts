export const MODULE_CAPABILITY_PROTOCOL_VERSION = 1 as const;

export const MODULE_CAPABILITY_NAMES = [
  "health.read",
  "backup.status",
  "files.search",
  "events.read"
] as const;

export type ModuleCapabilityName = (typeof MODULE_CAPABILITY_NAMES)[number] | `command.${string}`;
export type CapabilityDataClassification = "status" | "metadata" | "event" | "command-result";
export type CapabilityAuthRequirement = "bielos-session" | "module-local";
export type CapabilityAuthorizationRequirement = "principal-scoped" | "owner-only" | "module-local";
export type CapabilityAuditRequirement = "required" | "optional" | "none";

export type RequestedModuleCapability = {
  name: ModuleCapabilityName;
  version: number;
};

export type ModuleCapabilityDescriptor = {
  name: ModuleCapabilityName;
  version: 1;
  classification: CapabilityDataClassification;
  auth: CapabilityAuthRequirement;
  authorization: CapabilityAuthorizationRequirement;
  audit: CapabilityAuditRequirement;
  requestSchema: string;
  responseSchema: string;
  timeoutMs: number;
  maxRetries: number;
  idempotency: "required" | "optional" | "none";
  freshnessRequired: boolean;
  deprecated?: boolean;
};

export type ModuleCapabilityManifest = {
  protocolVersion: 1;
  module: {
    id: string;
    version: string;
  };
  capabilities: readonly ModuleCapabilityDescriptor[];
};

export type CapabilityProvenance = {
  source: string;
  observedAt: string;
  revision?: string;
};

export type CapabilityEnvelope<T> = {
  protocolVersion: 1;
  moduleId: string;
  capability: ModuleCapabilityName;
  generatedAt: string;
  freshnessMs: number;
  provenance: CapabilityProvenance;
  data: T;
};

export function isDeclaredCapability(
  manifest: ModuleCapabilityManifest,
  name: ModuleCapabilityName,
  version = 1
): boolean {
  return manifest.protocolVersion === MODULE_CAPABILITY_PROTOCOL_VERSION && manifest.capabilities.some(
    (capability) => capability.name === name && capability.version === version && capability.deprecated !== true
  );
}

export function negotiateModuleCapabilities(
  manifest: ModuleCapabilityManifest,
  requested: readonly RequestedModuleCapability[]
): ModuleCapabilityDescriptor[] {
  if (manifest.protocolVersion !== MODULE_CAPABILITY_PROTOCOL_VERSION) return [];
  return requested.flatMap((request) => {
    const match = manifest.capabilities.find(
      (capability) => capability.name === request.name && capability.version === request.version && capability.deprecated !== true
    );
    return match ? [match] : [];
  });
}

export function validateModuleCapabilityManifest(value: unknown): ModuleCapabilityManifest | null {
  if (!isRecord(value) || value.protocolVersion !== MODULE_CAPABILITY_PROTOCOL_VERSION || !isRecord(value.module) || !Array.isArray(value.capabilities)) {
    return null;
  }
  const moduleId = value.module.id;
  const moduleVersion = value.module.version;
  if (!isSafeToken(moduleId, 80) || typeof moduleVersion !== "string" || moduleVersion.length === 0 || moduleVersion.length > 40) {
    return null;
  }
  const capabilities: ModuleCapabilityDescriptor[] = [];
  const seenCapabilities = new Set<string>();
  for (const candidate of value.capabilities) {
    if (!isRecord(candidate) || !isCapabilityName(candidate.name) || candidate.version !== 1) return null;
    const capabilityKey = `${candidate.name}:${candidate.version}`;
    if (seenCapabilities.has(capabilityKey)) return null;
    seenCapabilities.add(capabilityKey);
    if (!isOneOf(candidate.classification, ["status", "metadata", "event", "command-result"] as const)) return null;
    if (!isOneOf(candidate.auth, ["bielos-session", "module-local"] as const)) return null;
    if (!isOneOf(candidate.authorization, ["principal-scoped", "owner-only", "module-local"] as const)) return null;
    if (!isOneOf(candidate.audit, ["required", "optional", "none"] as const)) return null;
    if (typeof candidate.requestSchema !== "string" || candidate.requestSchema.length > 120) return null;
    if (typeof candidate.responseSchema !== "string" || candidate.responseSchema.length > 120) return null;
    if (typeof candidate.timeoutMs !== "number" || !Number.isInteger(candidate.timeoutMs) || candidate.timeoutMs < 100 || candidate.timeoutMs > 10_000) return null;
    if (typeof candidate.maxRetries !== "number" || !Number.isInteger(candidate.maxRetries) || candidate.maxRetries < 0 || candidate.maxRetries > 3) return null;
    if (!isOneOf(candidate.idempotency, ["required", "optional", "none"] as const)) return null;
    if (typeof candidate.freshnessRequired !== "boolean") return null;
    if (candidate.deprecated !== undefined && typeof candidate.deprecated !== "boolean") return null;
    capabilities.push({
      name: candidate.name,
      version: 1,
      classification: candidate.classification,
      auth: candidate.auth,
      authorization: candidate.authorization,
      audit: candidate.audit,
      requestSchema: candidate.requestSchema,
      responseSchema: candidate.responseSchema,
      timeoutMs: candidate.timeoutMs,
      maxRetries: candidate.maxRetries,
      idempotency: candidate.idempotency,
      freshnessRequired: candidate.freshnessRequired,
      ...(candidate.deprecated === undefined ? {} : { deprecated: candidate.deprecated })
    });
  }
  return { protocolVersion: 1, module: { id: moduleId, version: moduleVersion }, capabilities };
}

export function validateCapabilityEnvelope(value: unknown): CapabilityEnvelope<unknown> | null {
  if (!isRecord(value) || value.protocolVersion !== MODULE_CAPABILITY_PROTOCOL_VERSION || !isSafeToken(value.moduleId, 80) || !isCapabilityName(value.capability)) return null;
  if (typeof value.generatedAt !== "string" || Number.isNaN(Date.parse(value.generatedAt))) return null;
  if (typeof value.freshnessMs !== "number" || !Number.isInteger(value.freshnessMs) || value.freshnessMs < 0 || value.freshnessMs > 86_400_000) return null;
  if (!isRecord(value.provenance) || !isSafeToken(value.provenance.source, 120) || typeof value.provenance.observedAt !== "string" || Number.isNaN(Date.parse(value.provenance.observedAt))) return null;
  if (value.provenance.revision !== undefined && !isSafeToken(value.provenance.revision, 128)) return null;
  return {
    protocolVersion: 1,
    moduleId: value.moduleId,
    capability: value.capability,
    generatedAt: value.generatedAt,
    freshnessMs: value.freshnessMs,
    provenance: {
      source: value.provenance.source,
      observedAt: value.provenance.observedAt,
      ...(value.provenance.revision === undefined ? {} : { revision: value.provenance.revision })
    },
    data: value.data
  };
}

function isCapabilityName(value: unknown): value is ModuleCapabilityName {
  return typeof value === "string" && (MODULE_CAPABILITY_NAMES.includes(value as (typeof MODULE_CAPABILITY_NAMES)[number]) || /^command\.[a-z0-9][a-z0-9._-]{0,63}$/.test(value));
}

function isSafeToken(value: unknown, maxLength: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength && /^[a-z0-9][a-z0-9._-]*$/.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isOneOf<T extends readonly string[]>(value: unknown, choices: T): value is T[number] {
  return typeof value === "string" && choices.includes(value);
}
