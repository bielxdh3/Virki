import { readFileSync } from 'node:fs';
import { createServer } from 'node:https';
import { Pool } from 'pg';
import { createVirkiOidcClient, randomRpSessionId } from '@virki/oidc-node';
import { EncryptedPostgresTransactionStore } from '@virki/oidc-node/postgres-store';
import { createRpHandler } from './server.mjs';
import { validateRpDatabaseConnection } from './database-config.mjs';
import { parseServerOrigin, sessionCryptoKey } from './security.mjs';

async function main() {
  const configured = process.env;
  if (Number(process.versions.node.split('.')[0]) !== 22) throw new Error('Requires Node 22.');
  const origin = parseServerOrigin(configured.RP_ORIGIN);
  const issuer = configured.OIDC_ISSUER;
  const confidentialCredential = configured.OIDC_CLIENT_SECRET;
  const redirectUri = configured.OIDC_REDIRECT_URI;
  if (new URL(redirectUri).origin !== origin.origin || new URL(redirectUri).pathname !== '/oidc/callback'
    || new URL(redirectUri).search || new URL(redirectUri).hash) throw new Error('RP callback mismatch.');
  if (!/^[a-fA-F0-9]{64}$/u.test(configured.RP_ENCRYPTION_KEY_HEX ?? '')) throw new Error('RP key unavailable.');
  const key = Buffer.from(configured.RP_ENCRYPTION_KEY_HEX, 'hex');
  validateRpDatabaseConnection(configured.RP_DATABASE_URL, configured.RP_DATABASE_SSL_CA_FILE);
  const pool = new Pool({
    connectionString: configured.RP_DATABASE_URL,
    max: 5, connectionTimeoutMillis: 5000, idleTimeoutMillis: 10_000,
    ...(configured.RP_DATABASE_SSL_CA_FILE ? { ssl: { ca: readFileSync(configured.RP_DATABASE_SSL_CA_FILE), rejectUnauthorized: true } } : {})
  });
  try {
    await pool.query('SELECT 1');
    const store = new EncryptedPostgresTransactionStore(pool, key);
    const accessSecret = configured.RP_ACCESS_CLIENT_SECRET;
    const cloudflareAccess = configured.RP_ACCESS_CLIENT_ID !== undefined || configured.RP_ACCESS_CLIENT_SECRET !== undefined
      ? { clientId: configured.RP_ACCESS_CLIENT_ID, clientSecret: accessSecret }
      : undefined;
    const oidc = await createVirkiOidcClient({
      issuer, clientId: configured.OIDC_CLIENT_ID, clientSecret: confidentialCredential,
      redirectUri, store, ...(cloudflareAccess ? { cloudflareAccess } : {})
    });
    const handler = createRpHandler({ oidc, db: pool, origin: origin.origin, issuer, sessionKey: sessionCryptoKey(key),
      revokeOnLogout: configured.RP_REVOKE_ON_LOGOUT !== 'false', generateId: randomRpSessionId });
    const server = createServer({
      key: readFileSync(configured.RP_TLS_KEY_FILE),
      cert: readFileSync(configured.RP_TLS_CERT_FILE),
      minVersion: 'TLSv1.2'
    }, handler);
    server.on('clientError', (_error, socket) => socket.destroy());
    server.listen(Number(origin.port) || 443, configured.RP_LISTEN_HOST || '127.0.0.1', () => {
      console.info('Virki RP sample is listening on its configured HTTPS endpoint.');
    });
    const close = () => server.close(() => { void pool.end(); });
    process.once('SIGINT', close);
    process.once('SIGTERM', close);
  } catch (error) {
    await pool.end();
    throw error;
  }
}

main().catch(() => {
  // No config values, credentials, callback URLs or token-grant stack traces.
  console.error('RP startup failed. Verify the local configuration, schema and SDK build.');
  process.exitCode = 1;
});
