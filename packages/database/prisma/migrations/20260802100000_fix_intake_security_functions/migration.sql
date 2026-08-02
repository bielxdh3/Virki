-- Avoid PL/pgSQL parameter/column name collisions in the intake capabilities.

DROP FUNCTION IF EXISTS "bielos_intake_activate_application"(TEXT, TEXT, TEXT, TIMESTAMP(3));

CREATE FUNCTION "bielos_intake_activate_application"(
  p_token_hash TEXT,
  p_user_id TEXT,
  p_password_hash TEXT,
  p_now_at TIMESTAMP(3)
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  activation RECORD;
  decision RECORD;
BEGIN
  SELECT
    activation."id" AS "activationId",
    application."id" AS "applicationId",
    application."emailNormalized",
    application."displayName",
    application."status"
  INTO activation
  FROM "AccountActivation" AS activation
  JOIN "AccountApplication" AS application
    ON application."id" = activation."applicationId"
  WHERE activation."tokenHash" = p_token_hash
    AND activation."consumedAt" IS NULL
    AND activation."expiresAt" > p_now_at
  FOR UPDATE OF activation, application;

  IF NOT FOUND OR activation."status" NOT IN ('APPROVED', 'PARTIALLY_APPROVED') THEN
    RETURN false;
  END IF;

  INSERT INTO "User" (
    "id", "email", "emailNormalized", "displayName", "passwordHash",
    "accountStatus", "emailVerifiedAt", "createdAt", "updatedAt"
  ) VALUES (
    p_user_id,
    activation."emailNormalized",
    activation."emailNormalized",
    activation."displayName",
    p_password_hash,
    'ACTIVE',
    p_now_at,
    p_now_at,
    p_now_at
  );

  FOR decision IN
    SELECT "moduleId", "accessDurationKind", "accessExpiresAt"
    FROM "ApplicationModuleDecision"
    WHERE "applicationId" = activation."applicationId"
      AND "status" = 'APPROVED'
  LOOP
    INSERT INTO "ModuleAccessGrant" (
      "id", "userId", "moduleId", "accessDurationKind", "expiresAt", "createdAt", "updatedAt"
    ) VALUES (
      substr(md5(random()::TEXT || clock_timestamp()::TEXT || p_user_id || decision."moduleId"), 1, 25),
      p_user_id,
      decision."moduleId",
      decision."accessDurationKind",
      decision."accessExpiresAt",
      p_now_at,
      p_now_at
    );
  END LOOP;

  UPDATE "AccountActivation"
  SET "consumedAt" = p_now_at, "updatedAt" = p_now_at
  WHERE "id" = activation."activationId" AND "consumedAt" IS NULL;

  UPDATE "AccountApplication"
  SET "status" = 'ACTIVATED', "activatedUserId" = p_user_id, "updatedAt" = p_now_at
  WHERE "id" = activation."applicationId";

  RETURN true;
END;
$$;

REVOKE ALL ON FUNCTION "bielos_intake_activate_application"(TEXT, TEXT, TEXT, TIMESTAMP(3)) FROM PUBLIC;

DROP FUNCTION IF EXISTS "bielos_intake_enqueue_email_message"(TEXT, TEXT, TEXT, JSONB, TIMESTAMP(3));

CREATE FUNCTION "bielos_intake_enqueue_email_message"(
  p_idempotency_key TEXT,
  p_recipient_email TEXT,
  p_locale TEXT,
  p_payload JSONB,
  p_available_at TIMESTAMP(3)
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  INSERT INTO "EmailOutboxMessage" (
    "id", "idempotencyKey", "kind", "recipientEmail", "locale", "payload", "availableAt", "updatedAt"
  ) VALUES (
    substr(md5(random()::TEXT || clock_timestamp()::TEXT || p_idempotency_key), 1, 25),
    p_idempotency_key,
    'APPLICATION_EMAIL_VERIFICATION',
    p_recipient_email,
    p_locale,
    p_payload,
    p_available_at,
    p_available_at
  )
  ON CONFLICT ("idempotencyKey") DO NOTHING;
END;
$$;

REVOKE ALL ON FUNCTION "bielos_intake_enqueue_email_message"(TEXT, TEXT, TEXT, JSONB, TIMESTAMP(3)) FROM PUBLIC;
