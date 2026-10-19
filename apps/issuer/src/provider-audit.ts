import { hashAuditIdentifier, type AuditLogInput } from "@virki/auth";

type ProviderAuditContext = {
  oidc?: {
    client?: { clientId?: unknown };
    session?: { accountId?: unknown };
    entities?: {
      Grant?: { accountId?: unknown };
      Account?: { accountId?: unknown };
    };
  };
};

type ProviderEventSpec = Pick<AuditLogInput, "eventType" | "result" | "resource" | "message"> & { error?: boolean };

const providerEventSpecs: Readonly<Record<string, ProviderEventSpec>> = {
  "userinfo.error": { eventType: "SSO_USERINFO_REJECTED", result: "FAILURE", resource: "sso.userinfo", message: "OIDC userinfo request rejected.", error: true },
  "revocation.error": { eventType: "SSO_REVOCATION_REJECTED", result: "FAILURE", resource: "sso.revocation", message: "OIDC token revocation request rejected.", error: true },
  "end_session.success": { eventType: "SSO_LOGOUT_COMPLETED", result: "SUCCESS", resource: "sso.logout", message: "OIDC logout completed." },
  "end_session.error": { eventType: "SSO_LOGOUT_REJECTED", result: "FAILURE", resource: "sso.logout", message: "OIDC logout request rejected.", error: true },
  "end_session_confirm.error": { eventType: "SSO_LOGOUT_REJECTED", result: "FAILURE", resource: "sso.logout", message: "OIDC logout confirmation rejected.", error: true },
  "end_session_success.error": { eventType: "SSO_LOGOUT_REJECTED", result: "FAILURE", resource: "sso.logout", message: "OIDC logout completion rejected.", error: true },
  server_error: { eventType: "SSO_PROVIDER_ERROR", result: "FAILURE", resource: "sso.provider", message: "OIDC provider encountered an internal error.", error: true }
};

export function createProviderEventAudit(eventName: string, context: ProviderAuditContext, error?: unknown): AuditLogInput | null {
  const spec = providerEventSpecs[eventName];
  if (!spec) return null;
  const oidc = context.oidc;
  const clientId = getString(oidc?.client?.clientId);
  const actorUserId = getString(oidc?.session?.accountId)
    ?? getString(oidc?.entities?.Grant?.accountId)
    ?? getString(oidc?.entities?.Account?.accountId);
  const metadata = {
    ...(clientId ? { clientRef: hashAuditIdentifier(clientId) } : {}),
    ...(spec.error ? { error: safeOidcError(error) } : {})
  };
  return {
    eventType: spec.eventType,
    result: spec.result,
    ...(actorUserId ? { actorUserId } : {}),
    resource: spec.resource,
    message: spec.message,
    ...(Object.keys(metadata).length ? { metadata } : {})
  };
}

function getString(value: unknown): string | undefined {
  return typeof value === "string" && value ? value : undefined;
}

function safeOidcError(value: unknown): string {
  if (!value || typeof value !== "object") return "server_error";
  const code = (value as { error?: unknown }).error;
  return typeof code === "string" && /^[a-z_]{3,40}$/u.test(code) ? code : "server_error";
}
