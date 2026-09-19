import type {
  CapabilityEnvelope,
  ModuleCapabilityManifest
} from "@bielos/types";
import type { BielosLocale } from "@bielos/ui";
import { validateModuleCapabilityManifest } from "@bielos/types";

import type { CoreOperationsSnapshot } from "./operations";

export type HealthState = "healthy" | "unknown" | "stale" | "unavailable";

export type HealthCard = {
  id: string;
  name: string;
  state: HealthState;
  summary: string;
  source: string;
  freshness: string;
  observedAt: string;
  details: readonly string[];
};

export type RecoveryCard = {
  id: string;
  name: string;
  state: "verified" | "unknown" | "unavailable";
  summary: string;
  source: string;
  freshness: string;
  observedAt: string;
  details: readonly string[];
};

export type ActivityEvent = {
  id: string;
  source: string;
  type: string;
  severity: "info" | "warning" | "critical";
  occurredAt: string;
  freshness: string;
  href: string;
};

export type AutomationRecipe = {
  id: string;
  version: 1;
  trigger: string;
  action: string;
  target: string;
  requiredCapabilities: readonly string[];
  status: "available" | "blocked";
  reason: string;
};

export const CORE_CAPABILITY_MANIFEST: ModuleCapabilityManifest = {
  protocolVersion: 1,
  module: { id: "bielos-core", version: "0.1.0" },
  capabilities: [
    {
      name: "health.read",
      version: 1,
      classification: "status",
      auth: "bielos-session",
      authorization: "principal-scoped",
      audit: "required",
      requestSchema: "CoreHealthRequestV1",
      responseSchema: "CoreHealthResponseV1",
      timeoutMs: 800,
      maxRetries: 0,
      idempotency: "none",
      freshnessRequired: true
    }
  ]
};

export const CORE_CAPABILITY_MANIFEST_VALID = Boolean(validateModuleCapabilityManifest(CORE_CAPABILITY_MANIFEST));

export function getCoreHealthCards(
  snapshot: CoreOperationsSnapshot,
  locale: BielosLocale = "pt-BR",
  observedAt = new Date().toISOString()
): HealthCard[] {
  const databaseHealthy = snapshot.database === "verified";
  const pt = locale === "pt-BR";
  const freshness = formatFreshness(observedAt, locale);
  return [
    {
      id: "bielos-core",
      name: "BielOS Core",
      state: databaseHealthy ? "healthy" : "unknown",
      summary: databaseHealthy ? (pt ? "Core responde" : "Core responds") : (pt ? "Estado do banco desconhecido" : "Database state unknown"),
      source: "BielOS Core",
      freshness,
      observedAt,
      details: [
        `${pt ? "Sessão" : "Session"}: ${snapshot.authenticatedSession === "verified" ? (pt ? "verificada" : "verified") : (pt ? "desconhecida" : "unknown")}`,
        `${pt ? "Banco" : "Database"}: ${databaseHealthy ? (pt ? "verificado" : "verified") : (pt ? "desconhecido" : "unknown")}`,
        `${pt ? "E-mail" : "Email"}: ${snapshot.emailTransport === "configured" ? (pt ? "configurado" : "configured") : (pt ? "indisponível" : "unavailable")}`
      ]
    },
    {
      id: "gymforge",
      name: "GymForge",
      state: "unavailable",
      summary: pt ? "Capability de saúde não declarada" : "Health capability not declared",
      source: pt ? "Limite GymForge" : "GymForge boundary",
      freshness,
      observedAt,
      details: [pt ? "O runtime permanece separado; nenhum endpoint interno é descoberto." : "Runtime remains separate; no internal endpoint is discovered."]
    }
  ];
}

export function getRecoveryCards(locale: BielosLocale = "pt-BR", observedAt = new Date().toISOString()): RecoveryCard[] {
  const pt = locale === "pt-BR";
  const freshness = formatFreshness(observedAt, locale);
  return [
    {
      id: "bielos-core",
      name: "BielOS Core",
      state: "unknown",
      summary: pt ? "Backup e restore não verificados nesta sessão" : "Backup and restore not verified in this session",
      source: pt ? "Contrato de recuperação" : "Recovery contract",
      freshness,
      observedAt,
      details: pt ? ["A existência de um backup não é inferida como recuperabilidade.", "Validação operacional continua documentada em Operations."] : ["A backup's existence is not inferred as recoverability.", "Operational validation remains documented in Operations."]
    },
    {
      id: "reserved-boundaries",
      name: "Root.ark · L-vault · H-vault",
      state: "unavailable",
      summary: pt ? "Boundary reservado" : "Reserved boundary",
      source: pt ? "Contrato de módulo" : "Module contract",
      freshness,
      observedAt,
      details: [pt ? "Nenhum dado protegido é copiado para o Core." : "Protected data is never copied into Core."]
    }
  ];
}

export function getActivityInboxEvents(): ActivityEvent[] {
  // No module currently declares events.read with a source-owned provider.
  return [];
}

export const AUTOMATION_RECIPES: readonly AutomationRecipe[] = [
  {
    id: "surface-stale-recovery",
    version: 1,
    trigger: "Recovery status becomes stale",
    action: "Create an inbox exception",
    target: "Authorized module",
    requiredCapabilities: ["backup.status", "events.read"],
    status: "blocked",
    reason: "Requires a declared provider and the bounded scheduler boundary."
  }
];

function formatFreshness(value: string, locale: BielosLocale): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? (locale === "pt-BR" ? "Não observado" : "Not observed")
    : date.toLocaleString(locale, { dateStyle: "short", timeStyle: "short" });
}

export type HealthEnvelope = CapabilityEnvelope<{ state: HealthState }>;
