import assert from "node:assert/strict";
import test from "node:test";
import { createOidcAuthRequestMarker, getOidcAuthenticationContext, hasValidOidcStateAndNonce, isCurrentActiveUserProjectGrant, isCurrentOidcAuthenticationContext, isOidcInteractionPathBound, OIDC_DISCOVERY_CONFIGURATION, OIDC_SUPPORTED_ACR_VALUES, readOidcAuthRequestMarker, requiresFreshOidcAuthentication, requiresOidcAssuranceInteraction, requiresProjectAccessInteraction, satisfiesEssentialOidcAcrValues, supportsEssentialOidcAcrValues } from "./authorization-policy";

const activeUserGrant = {
  revokedAt: null,
  user: { role: "USER", isActive: true, accountStatus: "ACTIVE" },
  connection: { enabled: true }
};

test("project authorization requires an active account, client, and grant", () => {
  assert.equal(requiresProjectAccessInteraction("account", "client", true), false);
  assert.equal(requiresProjectAccessInteraction("account", "client", false), true, "missing, revoked, and disabled access is denied");
  assert.equal(requiresProjectAccessInteraction(undefined, "client", true), false);
  assert.equal(requiresProjectAccessInteraction("account", undefined, true), false);
});

test("OIDC authorizes only current active USER grants on enabled connections", () => {
  assert.equal(isCurrentActiveUserProjectGrant(activeUserGrant), true);
  assert.equal(requiresProjectAccessInteraction("user", "client", isCurrentActiveUserProjectGrant(activeUserGrant)), false);

  const legacyAdminGrant = { ...activeUserGrant, user: { ...activeUserGrant.user, role: "ADMIN" } };
  assert.equal(isCurrentActiveUserProjectGrant(legacyAdminGrant), false);
  assert.equal(requiresProjectAccessInteraction("admin", "client", isCurrentActiveUserProjectGrant(legacyAdminGrant)), true, "legacy ADMIN grant rows never authorize project entry");
  assert.equal(isCurrentActiveUserProjectGrant({ ...activeUserGrant, user: { ...activeUserGrant.user, isActive: false } }), false);
  assert.equal(isCurrentActiveUserProjectGrant({ ...activeUserGrant, user: { ...activeUserGrant.user, accountStatus: "INACTIVE" } }), false);
  assert.equal(isCurrentActiveUserProjectGrant({ ...activeUserGrant, connection: { enabled: false } }), false);
  assert.equal(isCurrentActiveUserProjectGrant({ ...activeUserGrant, revokedAt: new Date() }), false);
  assert.equal(isCurrentActiveUserProjectGrant(null), false);
});

test("OIDC state is required and nonce is required for OpenID requests", () => {
  const opaqueValue = "0123456789abcdef";
  assert.equal(hasValidOidcStateAndNonce(opaqueValue, opaqueValue, true), true);
  assert.equal(hasValidOidcStateAndNonce(opaqueValue, "", true), false);
  assert.equal(hasValidOidcStateAndNonce("", "", false), false);
  assert.equal(hasValidOidcStateAndNonce(`${opaqueValue}\n`, opaqueValue, true), false);
});

test("OIDC authentication claims report the persisted methods and assurance level", () => {
  assert.deepEqual(OIDC_SUPPORTED_ACR_VALUES, ["urn:virki:loa:1", "urn:virki:loa:2"]);
  assert.deepEqual(OIDC_DISCOVERY_CONFIGURATION.acrValues, OIDC_SUPPORTED_ACR_VALUES);
  assert.deepEqual(OIDC_DISCOVERY_CONFIGURATION.features.claimsParameter, { enabled: true });
  assert.deepEqual(getOidcAuthenticationContext(["pwd"]), { acr: "urn:virki:loa:1", amr: ["pwd"] });
  assert.deepEqual(getOidcAuthenticationContext(["pwd", "otp", "mfa"]), { acr: "urn:virki:loa:2", amr: ["pwd", "otp", "mfa"] });
  assert.deepEqual(getOidcAuthenticationContext(["pwd", "mfa", "not allowed!"]), { acr: "urn:virki:loa:2", amr: ["pwd", "mfa"] });
  assert.deepEqual(getOidcAuthenticationContext(["pwd", "otp", "mfa"], ["urn:virki:loa:1"]), { acr: "urn:virki:loa:1", amr: ["pwd", "otp", "mfa"] });
  assert.equal(supportsEssentialOidcAcrValues(["urn:virki:loa:3"]), false);
  assert.equal(supportsEssentialOidcAcrValues(["urn:virki:loa:3", "urn:virki:loa:2"]), true);
  assert.equal(satisfiesEssentialOidcAcrValues(["urn:virki:loa:1"], ["pwd", "otp", "mfa"]), true);
  assert.equal(satisfiesEssentialOidcAcrValues(["urn:virki:loa:2"], ["pwd"]), false);
});

test("OIDC provider session assurance, methods, and auth time must match the current central session", () => {
  const authenticatedAt = new Date("2026-10-02T12:00:00.000Z");
  const currentLoginTs = Math.floor(authenticatedAt.getTime() / 1_000);

  assert.equal(isCurrentOidcAuthenticationContext({
    currentAcr: "urn:virki:loa:2",
    currentAmr: ["pwd", "otp", "mfa"],
    currentLoginTs,
    authenticationMethods: ["pwd", "otp", "mfa"],
    authenticatedAt
  }), true);
  assert.equal(isCurrentOidcAuthenticationContext({
    currentAcr: "urn:virki:loa:1",
    currentAmr: ["pwd", "otp", "mfa"],
    currentLoginTs,
    authenticationMethods: ["pwd", "otp", "mfa"],
    authenticatedAt
  }), true, "the provider may persist loa1 when the client requires loa1, even with current MFA methods");
  assert.equal(isCurrentOidcAuthenticationContext({
    currentAcr: "urn:virki:loa:2",
    currentAmr: ["pwd", "otp", "mfa"],
    currentLoginTs: currentLoginTs - 60,
    authenticationMethods: ["pwd"],
    authenticatedAt
  }), false, "a same-user password-only session must not reuse old MFA claims");
  assert.equal(isCurrentOidcAuthenticationContext({
    currentAcr: "urn:virki:loa:1",
    currentAmr: ["pwd"],
    currentLoginTs,
    authenticationMethods: ["pwd"],
    authenticatedAt
  }), true);
  assert.equal(isCurrentOidcAuthenticationContext({
    currentAcr: "urn:virki:loa:1",
    currentAmr: ["pwd"],
    currentLoginTs: currentLoginTs - 1,
    authenticationMethods: ["pwd"],
    authenticatedAt
  }), false, "auth_time must be refreshed after a new central session");
});

test("OIDC ACR loa:2 creates an interaction unless the provider session has current MFA assurance", () => {
  assert.equal(requiresOidcAssuranceInteraction({ requestedAcrValues: "urn:virki:loa:2", currentAcr: "urn:virki:loa:1", authenticationMethods: ["pwd", "otp", "mfa"] }), true);
  assert.equal(requiresOidcAssuranceInteraction({ requestedAcrValues: "urn:virki:loa:2", currentAcr: "urn:virki:loa:2", authenticationMethods: ["pwd", "otp", "mfa"] }), false);
  assert.equal(requiresOidcAssuranceInteraction({ requestedAcrValues: "urn:virki:loa:2", currentAcr: "urn:virki:loa:1", authenticationMethods: ["pwd"] }), true);
  assert.equal(requiresOidcAssuranceInteraction({ requestedAcrValues: "urn:virki:loa:1", currentAcr: "urn:virki:loa:1", authenticationMethods: ["pwd"] }), false);
});

test("OIDC authentication request markers bind proof timestamps to one interaction", () => {
  const key = Buffer.alloc(32, 7);
  const marker = createOidcAuthRequestMarker("interaction_123", 1_798_000_000_000, key);
  assert.equal(readOidcAuthRequestMarker(marker, "interaction_123", key, 1_798_000_000_500), 1_798_000_000_000);
  assert.equal(readOidcAuthRequestMarker(marker, "interaction_other", key, 1_798_000_000_500), null);
  assert.equal(readOidcAuthRequestMarker(`${marker.slice(0, -1)}A`, "interaction_123", key, 1_798_000_000_500), null);
  assert.equal(readOidcAuthRequestMarker(marker, "interaction_123", key, 1_798_000_901_000), null);
});

test("OIDC interaction routes are bound to the interaction selected by the provider cookie", () => {
  assert.equal(isOidcInteractionPathBound("interaction_123", "interaction_123"), true);
  assert.equal(isOidcInteractionPathBound("interaction_other", "interaction_123"), false);
});

test("OIDC prompt=login and max_age require recent central authentication", () => {
  const now = new Date("2026-10-01T12:00:00.000Z");
  const authenticationMethods = ["pwd", "otp", "mfa"];
  const requestStartedAtMs = now.getTime();
  assert.equal(requiresFreshOidcAuthentication({ prompt: "login", maxAge: undefined, requestStartedAtMs, authenticatedAt: new Date(now.getTime() - 5_000), authenticationMethods, now }), true);
  assert.equal(requiresFreshOidcAuthentication({ prompt: "login", maxAge: undefined, requestStartedAtMs, authenticatedAt: now, authenticationMethods, now }), true);
  assert.equal(requiresFreshOidcAuthentication({ prompt: "login", maxAge: undefined, requestStartedAtMs, authenticatedAt: new Date(now.getTime() + 1), authenticationMethods, now }), false);
  assert.equal(requiresFreshOidcAuthentication({ prompt: "consent login", maxAge: undefined, requestStartedAtMs, authenticatedAt: new Date(now.getTime() + 1_000), authenticationMethods, now }), false);
  assert.equal(requiresFreshOidcAuthentication({ prompt: undefined, maxAge: 0, requestStartedAtMs, authenticatedAt: now, authenticationMethods, now }), true, "max_age=0 rejects proof from earlier in the same second");
  assert.equal(requiresFreshOidcAuthentication({ prompt: undefined, maxAge: 0, requestStartedAtMs, authenticatedAt: new Date(now.getTime() + 1), authenticationMethods, now }), false);
  assert.equal(requiresFreshOidcAuthentication({ prompt: undefined, maxAge: "30", requestStartedAtMs, authenticatedAt: new Date(now.getTime() - 31_000), authenticationMethods, now }), true);
  assert.equal(requiresFreshOidcAuthentication({ prompt: undefined, maxAge: "30", requestStartedAtMs, authenticatedAt: new Date(now.getTime() - 30_000), authenticationMethods, now }), false);
  assert.equal(requiresFreshOidcAuthentication({ prompt: undefined, maxAge: "30", requestStartedAtMs: now.getTime() + 900, authenticatedAt: new Date(now.getTime() + 1_100), authenticationMethods, now }), false, "proof completed after the request remains fresh across a second boundary");
  assert.equal(requiresFreshOidcAuthentication({ prompt: undefined, maxAge: 30, requestStartedAtMs, authenticatedAt: new Date(now.getTime() - 31_000), authenticationMethods, now }), true, "numeric default_max_age values are enforced");
  assert.equal(requiresFreshOidcAuthentication({ prompt: undefined, maxAge: "invalid", requestStartedAtMs, authenticatedAt: now, authenticationMethods, now }), true);
  assert.equal(requiresFreshOidcAuthentication({ prompt: undefined, maxAge: undefined, requestedAcrValues: "urn:virki:loa:2", requestStartedAtMs, authenticatedAt: now, authenticationMethods: ["pwd"], now }), true);
  assert.equal(requiresFreshOidcAuthentication({ prompt: undefined, maxAge: undefined, requestedAcrValues: "urn:virki:loa:2", requestStartedAtMs, authenticatedAt: new Date(now.getTime() + 1), authenticationMethods: ["pwd"], now }), true, "MFA assurance is required even when a password-only session is new");
  assert.equal(requiresFreshOidcAuthentication({ prompt: undefined, maxAge: undefined, requiredAcrValues: ["urn:virki:loa:2"], requestStartedAtMs, authenticatedAt: now, authenticationMethods: ["pwd"], now }), true);
});
