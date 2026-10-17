-- Historical attribution survives account suspension and cannot be rewritten by a parent-key cascade.
ALTER TABLE "AuditLog" DROP CONSTRAINT "AuditLog_actorUserId_fkey";
ALTER TABLE "AuditLog" ADD CONSTRAINT "AuditLog_actorUserId_fkey"
  FOREIGN KEY ("actorUserId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;
