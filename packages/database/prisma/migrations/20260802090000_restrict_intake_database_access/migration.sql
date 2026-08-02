-- Keep public intake on a narrow view and activation behind a controlled function.
-- The intake role is provisioned outside migrations and receives no direct access
-- to private Core, session, audit, administrative, or GymForge tables.

CREATE VIEW "IntakePublicModuleCatalog" AS
SELECT "id", "key", "name", "runtimeAvailability"
FROM "ModuleCatalog"
WHERE "visibility" = 'PUBLIC' AND "requestable" = true;

CREATE FUNCTION "bielos_intake_activate_application"(
  "tokenHash" TEXT,
  "userId" TEXT,
  "passwordHash" TEXT,
  "nowAt" TIMESTAMP(3)
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
  WHERE activation."tokenHash" = "tokenHash"
    AND activation."consumedAt" IS NULL
    AND activation."expiresAt" > "nowAt"
  FOR UPDATE OF activation, application;

  IF NOT FOUND OR activation."status" NOT IN ('APPROVED', 'PARTIALLY_APPROVED') THEN
    RETURN false;
  END IF;

  INSERT INTO "User" (
    "id",
    "email",
    "emailNormalized",
    "displayName",
    "passwordHash",
    "accountStatus",
    "emailVerifiedAt",
    "createdAt",
    "updatedAt"
  ) VALUES (
    "userId",
    activation."emailNormalized",
    activation."emailNormalized",
    activation."displayName",
    "passwordHash",
    'ACTIVE',
    "nowAt",
    "nowAt",
    "nowAt"
  );

  FOR decision IN
    SELECT "moduleId", "accessDurationKind", "accessExpiresAt"
    FROM "ApplicationModuleDecision"
    WHERE "applicationId" = activation."applicationId"
      AND "status" = 'APPROVED'
  LOOP
    INSERT INTO "ModuleAccessGrant" (
      "id",
      "userId",
      "moduleId",
      "accessDurationKind",
      "expiresAt",
      "createdAt",
      "updatedAt"
    ) VALUES (
      substr(md5(random()::TEXT || clock_timestamp()::TEXT || "userId" || decision."moduleId"), 1, 25),
      "userId",
      decision."moduleId",
      decision."accessDurationKind",
      decision."accessExpiresAt",
      "nowAt",
      "nowAt"
    );
  END LOOP;

  UPDATE "AccountActivation"
  SET "consumedAt" = "nowAt", "updatedAt" = "nowAt"
  WHERE "id" = activation."activationId" AND "consumedAt" IS NULL;

  UPDATE "AccountApplication"
  SET "status" = 'ACTIVATED', "activatedUserId" = "userId", "updatedAt" = "nowAt"
  WHERE "id" = activation."applicationId";

  RETURN true;
END;
$$;

REVOKE ALL ON FUNCTION "bielos_intake_activate_application"(TEXT, TEXT, TEXT, TIMESTAMP(3)) FROM PUBLIC;
