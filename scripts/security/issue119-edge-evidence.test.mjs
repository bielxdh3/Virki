import test from 'node:test';
import assert from 'node:assert/strict';
import { EDGE_HOSTS, TLS_PROBES, classifyTlsProbe, collectEdgeEvidence } from './issue119-edge-evidence.mjs';

const success = (protocol) => ({ status: 0, stdout: '', stderr: `CONNECTION ESTABLISHED\nProtocol version: ${protocol}\n` });
const refusal = () => ({ status: 1, stdout: '', stderr: 'tlsv1 alert protocol version\nSSL alert number 70\n' });

test('edge TLS evidence requires rejection of both legacy versions and acceptance of 1.2 and 1.3 at all three hosts', () => {
  const calls = [];
  const evidence = collectEdgeEvidence((host, probe) => {
    calls.push([host, probe.flag]);
    return probe.permitted ? success(probe.expected) : refusal();
  });
  assert.equal(evidence.passed, true);
  assert.equal(evidence.checks.length, 12);
  assert.deepEqual([...new Set(calls.map(([host]) => host))], EDGE_HOSTS);
  assert.deepEqual(calls.slice(0, 4).map(([, flag]) => flag), TLS_PROBES.map(({ flag }) => flag));
  assert.ok(evidence.checks.every((c) => c.observed === (c.required === 'accept' ? 'accepted' : 'rejected_by_peer')));
});

test('accepted TLS 1.0/1.1 fails the gate even when all modern handshakes succeed', () => {
  const evidence = collectEdgeEvidence((host, probe) =>
    host === 'portal.biel.dev.br' && probe.expected === 'TLSv1.1'
      ? success(probe.expected)
      : probe.permitted ? success(probe.expected) : refusal());
  assert.equal(evidence.passed, false);
  assert.equal(evidence.checks.find((c) => c.host === 'portal.biel.dev.br' && c.protocol === 'TLSv1.1').observed, 'accepted');
});

test('local OpenSSL errors, cipher rejection and missing modern protocol are inconclusive, never counted as pass', () => {
  for (const error of ['no protocols available', 'unknown option -tls1', 'sslv3 alert handshake failure', 'connect: Connection refused']) {
    assert.equal(classifyTlsProbe(TLS_PROBES[0], { status: 1, stderr: error }), 'inconclusive');
  }
  assert.equal(classifyTlsProbe(TLS_PROBES[2], { status: 1, stderr: 'alert protocol version' }), 'inconclusive');
  assert.equal(classifyTlsProbe(TLS_PROBES[2], success('TLSv1.3')), 'inconclusive');
  assert.equal(collectEdgeEvidence((_host, probe) => probe.permitted ? { status: 1, stderr: 'no protocols available' } : refusal()).passed, false);
});
