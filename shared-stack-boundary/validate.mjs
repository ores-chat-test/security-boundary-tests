#!/usr/bin/env node

import { readFile } from 'node:fs/promises';

const FIXTURE = new URL('./cases.json', import.meta.url);
const RATE_KEY = /^ores:rl:v1:[a-f0-9]{64}$/;
const ALLOWED_TELEMETRY = new Set([
  'client.identity_source',
  'http.status_code',
  'rate.decision',
  'rate.policy',
  'request.id',
  'route.id',
  'tenant.hash',
  'principal.hash',
]);
const FORBIDDEN_TELEMETRY = /(?:authorization|cookie|token|secret|password|database|connection|string|prompt|answer|body|document|signature|initial|email|phone|address|ip(?:\.|$)|claim|session)/i;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function sanitizeTelemetry(attributes, additions) {
  const keys = new Set();
  for (const key of Object.keys(attributes ?? {})) {
    if (ALLOWED_TELEMETRY.has(key) && !FORBIDDEN_TELEMETRY.test(key)) keys.add(key);
  }
  for (const key of additions) {
    if (ALLOWED_TELEMETRY.has(key)) keys.add(key);
  }
  return [...keys].sort();
}

function result(input, status, reason, details = {}) {
  const rateDecision = details.rateDecision ?? reason;
  const telemetryKeys = sanitizeTelemetry(input.telemetryAttributes, [
    'client.identity_source',
    'http.status_code',
    'request.id',
    'route.id',
    ...(details.rateLimitChecked ? ['rate.decision', 'rate.policy'] : []),
  ]);
  return {
    status,
    reason,
    startupAccepted: details.startupAccepted ?? true,
    clientIdentitySource: details.clientIdentitySource ?? 'unresolved',
    rateLimitChecked: details.rateLimitChecked ?? false,
    redisChecked: details.redisChecked ?? false,
    rateDecision,
    telemetryKeys,
  };
}

function evaluate(input) {
  assert(input && typeof input === 'object' && !Array.isArray(input), 'input must be an object');
  assert(['production', 'staging', 'test'].includes(input.environment), 'environment is invalid');
  assert(typeof input.routeId === 'string' && input.routeId.length > 0, 'routeId is required');
  assert(['public', 'customer', 'admin', 'internal'].includes(input.routeRealm), 'routeRealm is invalid');
  assert(Array.isArray(input.supportedConsistencyModes), 'supportedConsistencyModes is required');

  if (input.environment === 'production' && (input.testBypassEnabled || input.faultInjectionEnabled)) {
    return result(input, 500, 'unsafe-test-controls', {
      startupAccepted: false,
      clientIdentitySource: 'unresolved',
    });
  }

  const clientIdentitySource = input.peerTrusted && input.forwardedIdentityPresent
    ? 'trusted-forwarded'
    : 'peer';

  if (!input.actor?.active) {
    return result(input, 401, 'unauthenticated', { clientIdentitySource });
  }
  if (input.actor.realm !== input.routeRealm && input.routeRealm !== 'public') {
    return result(input, 403, 'realm-mismatch', { clientIdentitySource });
  }
  if (input.routeRealm === 'admin' && input.actor.mfa !== true) {
    return result(input, 403, 'admin-assurance-required', { clientIdentitySource });
  }

  if (!input.supportedConsistencyModes.includes(input.requestedConsistency)) {
    return result(input, 500, 'unsupported-consistency', { clientIdentitySource });
  }
  if (!RATE_KEY.test(input.rateKey ?? '')) {
    return result(input, 500, 'nonopaque-rate-key', { clientIdentitySource });
  }
  if (!['miss', 'deny', 'allow'].includes(input.localCacheDecision)) {
    return result(input, 500, 'invalid-local-cache-decision', { clientIdentitySource });
  }
  if (input.localCacheDecision === 'allow') {
    return result(input, 500, 'unsafe-local-permit-cache', {
      clientIdentitySource,
      rateLimitChecked: true,
    });
  }
  if (input.localCacheDecision === 'deny') {
    return result(input, 429, 'local-denial-cache', {
      clientIdentitySource,
      rateLimitChecked: true,
      redisChecked: false,
      rateDecision: 'deny',
    });
  }

  if (!['allow', 'deny', 'unavailable'].includes(input.redisDecision)) {
    return result(input, 500, 'invalid-redis-decision', {
      clientIdentitySource,
      rateLimitChecked: true,
    });
  }
  if (input.redisDecision === 'unavailable') {
    return result(input, 503, 'redis-unavailable', {
      clientIdentitySource,
      rateLimitChecked: true,
      redisChecked: true,
      rateDecision: 'unavailable',
    });
  }
  if (input.redisDecision === 'deny') {
    return result(input, 429, 'redis-denied', {
      clientIdentitySource,
      rateLimitChecked: true,
      redisChecked: true,
      rateDecision: 'deny',
    });
  }
  return result(input, 200, 'allowed', {
    clientIdentitySource,
    rateLimitChecked: true,
    redisChecked: true,
    rateDecision: 'allow',
  });
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  }
  return value;
}

const fixtureText = await readFile(FIXTURE, 'utf8');
assert(!/(?:ghp_|lin_api_|postgres(?:ql)?:\/\/|BEGIN (?:RSA |OPENSSH )?PRIVATE KEY)/i.test(fixtureText), 'fixture contains prohibited credential-shaped material');
const fixture = JSON.parse(fixtureText);
assert(fixture.schemaVersion === 'ores.shared-stack-boundary.cases.v1', 'unsupported fixture schema');
assert(Array.isArray(fixture.cases) && fixture.cases.length >= 12, 'at least twelve adversarial cases are required');
const ids = new Set();
for (const testCase of fixture.cases) {
  assert(typeof testCase.id === 'string' && testCase.id.length > 0, 'case id is required');
  assert(!ids.has(testCase.id), `duplicate case id: ${testCase.id}`);
  ids.add(testCase.id);
  const actual = stable(evaluate(testCase.input));
  const expected = stable(testCase.expected);
  assert(JSON.stringify(actual) === JSON.stringify(expected), `${testCase.id} mismatch\nexpected=${JSON.stringify(expected)}\nactual=${JSON.stringify(actual)}`);
  for (const key of actual.telemetryKeys) {
    assert(!FORBIDDEN_TELEMETRY.test(key), `${testCase.id} retained forbidden telemetry key ${key}`);
  }
}

process.stdout.write(`${JSON.stringify({
  schemaVersion: 'ores.shared-stack-boundary.receipt.v1',
  status: 'passed',
  cases: fixture.cases.length,
  invariants: [
    'auth-before-rate-limit',
    'realm-and-admin-assurance',
    'trusted-proxy-only',
    'opaque-rate-key',
    'local-cache-denials-only',
    'redis-fail-closed',
    'telemetry-key-allowlist',
    'production-test-controls-disabled',
  ],
})}\n`);
