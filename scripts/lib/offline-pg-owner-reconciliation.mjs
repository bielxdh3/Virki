// Disposable-only transaction around a separately protected Windows owner
// journal. A lost Docker response is NEVER proof a container will not appear.
// The caller supplies only the fixed signed-CLI transport and protected
// ACL-based journal; this helper does not authorize Docker operations itself.
const ID = /^[a-f0-9]{64}$/u;
const NAME = /^virki-disposable-pg-([a-f0-9]{32})$/u;
function refuse() { throw new Error("Disposable PostgreSQL owner reconciliation required."); }
const absent = (reply) => reply && !reply.error && reply.status !== 0 &&
  typeof reply.stderr === "string" && /no such object|no such container/iu.test(reply.stderr);

/**
 * Protect owner intent BEFORE run. Remove only a verified immutable ID, then
 * verify it is gone. If command acknowledgment is ambiguous retain the intent
 * forever, even if an immediately absent inspection may precede a late create.
 */
export function runWithDurablePgOwnerIntent({
  name, owner, journal, launch, inspect, remove, expectedExitCode = 0,
} = {}) {
  const match = NAME.exec(name ?? "");
  if (!match || owner !== match[1] || !journal ||
      (expectedExitCode !== 0 && expectedExitCode !== 97) ||
      [journal.create, journal.append, journal.clear, launch, inspect, remove]
        .some((f) => typeof f !== "function")) refuse();
  let result;
  let created = false;
  try {
    journal.create();
    created = true;
    try { result = launch(); } catch { result = { status: null, error: true }; }
    // Exit 97 is the sole checked-in malicious-URL negative fixture. A genuine
    // CLI acknowledgment of that exact deterministic early refusal is not a
    // lost reply. Every other nonzero/timeout remains unreconciled.
    const acknowledged = result?.status === expectedExitCode && !result?.error;
    const observed = inspect(name);
    if (observed?.status === 0 && !observed.error) {
      const [id, observedName, observedOwner] = String(observed.stdout ?? "").trim().split("|");
      if (!ID.test(id) || observedName !== `/${name}` || observedOwner !== owner) refuse();
      journal.append(id);
      const cleanup = remove(id);
      if (cleanup?.error || cleanup?.status !== 0) refuse();
      const confirmed = inspect(id);
      if (!absent(confirmed)) refuse();
    } else if (!absent(observed)) {
      refuse();
    }
    if (!acknowledged) refuse();
    journal.clear();
    return result;
  } catch {
    // No journal deletion on failure. In particular, an error after `create`
    // may race a delayed container and must be manually reconciled.
    if (created) refuse();
    refuse();
  }
}
