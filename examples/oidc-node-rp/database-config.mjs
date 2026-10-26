/** Keep PostgreSQL TLS settings out of the connection-string parser's override path. */
export function validateRpDatabaseConnection(connectionString, pinnedCaFile) {
  if (typeof connectionString !== 'string' || connectionString.trim() !== connectionString) {
    throw new Error('RP database unavailable.');
  }
  let url;
  try { url = new URL(connectionString); } catch { throw new Error('RP database unavailable.'); }
  if (!['postgresql:', 'postgres:'].includes(url.protocol) || !url.hostname
    || url.search || url.hash) {
    // node-postgres parses connectionString *after* supplied ssl options, so
    // ?ssl=0, ?ssl=no-verify, sslrootcert and similar parameters can replace
    // our pinned TLS CA. Deny all URL query options instead of maintaining an
    // incomplete list of security-sensitive aliases.
    throw new Error('RP database connection URL options are forbidden.');
  }
  const isLoopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (!isLoopback && (typeof pinnedCaFile !== 'string' || !pinnedCaFile.trim())) {
    throw new Error('Remote PostgreSQL requires pinned TLS CA.');
  }
  return { isLoopback };
}
