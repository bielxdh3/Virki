# BielOS administrative elevation

Administrative credentials are independent from the normal password. The owner setup ceremony requires an active owner session, the normal password, verified email, and a one-time email code. Administrative recovery uses the normal password, verified email state, and one offline administrative recovery code. Only hashes are stored; passwords and recovery codes are never emailed or audited.

Elevation is versioned (`protocolVersion = 1`) and bound to the owner, current session, exact critical scope, and duration. A timed elevation supports 15 minutes, 1 hour, 4 hours, or 24 hours. Manual-until-revoked elevation requires an explicit confirmation and remains visible until revoked, the session ends, the user is disabled, or credential recovery invalidates it.

The guarded scopes cover application review and activation reissue, module and feature access changes, account state/recovery approval, global-role changes, module catalog changes, administrative credential changes, administrative recovery-code regeneration, project-owner access changes, and Core project archive. Reads and the user’s own request status do not require elevation. Legacy `SecurityUnlock` approval rows are intentionally ignored.

Production readiness requires the owner to configure and acknowledge offline administrative recovery codes, then perform an authorized smoke test of start, email verification, scope binding, expiry, and revocation.
