import assert from 'node:assert/strict';
import { test } from 'node:test';
import { validateRpDatabaseConnection } from './database-config.mjs';

const remote = 'postgresql://db.example.invalid:5432/rp_test';
const loopback = 'postgresql://localhost:5432/rp_test';

test('remote RP database requires an explicitly pinned CA and no connection-string overrides', () => {
  assert.throws(() => validateRpDatabaseConnection(remote, undefined));
  assert.deepEqual(validateRpDatabaseConnection(remote, '/synthetic/privately-provisioned/ca.pem'),
    { isLoopback: false });
  for (const query of [
    '?ssl=0', '?ssl=no-verify', '?ssl=true', '?sslmode=disable',
    '?sslmode=prefer', '?sslrootcert=attacker.pem', '?sslcert=other.pem',
    '?sslkey=other.pem', '?sslnegotiation=direct', '?application_name=other',
    '?ssl%6dode=disable'
  ]) {
    assert.throws(() => validateRpDatabaseConnection(remote + query, '/synthetic/ca.pem'), undefined,
      `A query-string override must not reach node-postgres: ${query}`);
  }
});

test('local RP database accepts an ordinary URL but no hidden TLS flags or fragments', () => {
  assert.deepEqual(validateRpDatabaseConnection(loopback, undefined), { isLoopback: true });
  for (const unsafe of [
    loopback + '?ssl=0', loopback + '?ssl=no-verify', loopback + '#fragment',
    'http://localhost/rp', 'postgresql://synthetic@db.example.invalid/rp'
  ]) {
    assert.throws(() => validateRpDatabaseConnection(unsafe, undefined));
  }
});
