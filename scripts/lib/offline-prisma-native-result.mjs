// DEV-only evidence predicates. Text containing a Prisma error code is not
// evidence that the corresponding Docker/Prisma child exited normally.
export function isVerifiedPrismaInvocationResult(output, {
  expectedCode = null, expectFailure = false,
} = {}) {
  if (!output || output.error || output.signal !== null ||
      !Number.isSafeInteger(output.status)) return false;
  if (!expectFailure && expectedCode === null) return output.status === 0;
  if (output.status <= 0) return false;
  if (expectedCode === null) return true;
  if (expectedCode !== "P1003" && expectedCode !== "P3009") return false;
  const observed = `${output.stdout ?? ""}\n${output.stderr ?? ""}`;
  return new RegExp(`\\b${expectedCode}\\b`, "u").test(observed);
}

// A successful test must not produce a success receipt while leaving an
// uncertain Docker container or socket volume owned by this very test run.
// Failed runs retain their protected journal for later reconciliation.
export function isVerifiedSuccessfulCleanup({
  finished, cleaned, createdCount, volumeAttempted, volumeAccepted,
} = {}) {
  return finished !== true || (cleaned === true && createdCount === 2 &&
    volumeAttempted === true && volumeAccepted === true);
}
