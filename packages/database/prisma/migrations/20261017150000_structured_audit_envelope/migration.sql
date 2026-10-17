-- Additive only: legacy events retain their exact content and attribution.
ALTER TABLE "AuditLog"
  ADD COLUMN "schemaVersion" INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN "category" TEXT NOT NULL DEFAULT 'LEGACY',
  ADD COLUMN "severity" TEXT NOT NULL DEFAULT 'UNKNOWN',
  ADD COLUMN "action" TEXT,
  ADD COLUMN "reason" TEXT,
  ADD COLUMN "actorRef" TEXT,
  ADD COLUMN "actorRole" TEXT,
  ADD COLUMN "targetRef" TEXT,
  ADD COLUMN "sessionRef" TEXT,
  ADD COLUMN "deviceRef" TEXT,
  ADD COLUMN "requestId" TEXT,
  ADD COLUMN "service" TEXT,
  ADD COLUMN "route" TEXT,
  ADD COLUMN "method" TEXT,
  ADD COLUMN "networkProvenance" TEXT NOT NULL DEFAULT 'unavailable',
  ADD COLUMN "beforeState" JSONB,
  ADD COLUMN "afterState" JSONB;
CREATE INDEX "AuditLog_createdAt_id_idx" ON "AuditLog"("createdAt", "id");
CREATE INDEX "AuditLog_category_createdAt_id_idx" ON "AuditLog"("category", "createdAt", "id");
CREATE INDEX "AuditLog_result_createdAt_id_idx" ON "AuditLog"("result", "createdAt", "id");
CREATE INDEX "AuditLog_actorRef_createdAt_id_idx" ON "AuditLog"("actorRef", "createdAt", "id");
CREATE INDEX "AuditLog_resource_createdAt_id_idx" ON "AuditLog"("resource", "createdAt", "id");
CREATE INDEX "AuditLog_requestId_idx" ON "AuditLog"("requestId");
CREATE INDEX "AuditLog_action_idx" ON "AuditLog"("action");
-- Keep runtime INSERT/SELECT and maintenance privileges exactly as previously granted.
