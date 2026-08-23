import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeWorld, SUITE_UID_SECRET } from '../src/attacks.js';
import { hashUid, newEvent, signEvent } from '../src/events.js';
import { InMemoryNonceStore } from '../src/nonces.js';
import { markEligible } from '../src/registry.js';
import { verifySignedEvent } from '../src/verify.js';

const NOW = 1755860000000;
const ALICE_HASH = hashUid('alice', SUITE_UID_SECRET);

function acceptedEvent(world) {
  const event = newEvent({
    app_id: 'demo-app',
    key_id: 'k-2026-active',
    action_class: 'A',
    action_id: 'complete_transaction',
    weight: 50,
    pioneer_uid: 'x',
    uidSecret: SUITE_UID_SECRET,
    now: NOW
  });
  event.pioneer_uid_hash = ALICE_HASH;
  return signEvent(event, world.currentKey.private_key_pem);
}

test('happy path: every check passes and verdict is ACCEPT', () => {
  const world = makeWorld();
  const result = verifySignedEvent(acceptedEvent(world), {
    registry: world.registry,
    nonceStore: new InMemoryNonceStore(),
    now: NOW
  });
  assert.equal(result.ok, true);
  assert.deepEqual(result.checks.map((c) => c.check), [
    'SCHEMA',
    'APP_KNOWN',
    'KEY_ACTIVE',
    'CANONICALIZATION',
    'SIGNATURE',
    'TIMESTAMP_FRESHNESS',
    'WEIGHT_BOUND',
    'ELIGIBILITY',
    'NONCE_REPLAY'
  ]);
  assert.ok(result.checks.every((c) => c.pass));
});

test('verification is deterministic: same input, same result shape', () => {
  const world = makeWorld();
  const signed = acceptedEvent(world);
  const r1 = verifySignedEvent(signed, { registry: world.registry, nonceStore: new InMemoryNonceStore(), now: NOW });
  const r2 = verifySignedEvent(signed, { registry: world.registry, nonceStore: new InMemoryNonceStore(), now: NOW });
  assert.deepEqual(r1.checks, r2.checks);
  assert.equal(r1.ok, r2.ok);
});

test('failed verification does not burn the nonce', () => {
  const world = makeWorld();
  const store = new InMemoryNonceStore();
  const signed = acceptedEvent(world);

  const before = verifySignedEvent(signed, { registry: makeWorldEmpty(), nonceStore: store, now: NOW });
  assert.equal(before.code, 'UNKNOWN_APP');

  const after = verifySignedEvent(signed, { registry: world.registry, nonceStore: store, now: NOW });
  assert.equal(after.ok, true);
});

function makeWorldEmpty() {
  return { version: 1, apps: {}, eligible_users: [] };
}

test('non-object input is rejected with SCHEMA code', () => {
  const world = makeWorld();
  const result = verifySignedEvent('{"evil":true}', {
    registry: world.registry,
    nonceStore: new InMemoryNonceStore()
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, 'SCHEMA');
});

test('eligible-user gating consults the registry, not just self-declared flags', () => {
  const world = makeWorld();
  world.registry.eligible_users = {};
  const signed = acceptedEvent(world);
  const result = verifySignedEvent(signed, {
    registry: world.registry,
    nonceStore: new InMemoryNonceStore(),
    now: NOW
  });
  assert.equal(result.code, 'INELIGIBLE_USER');

  markEligible(world.registry, ALICE_HASH);
  const again = verifySignedEvent(signed, {
    registry: world.registry,
    nonceStore: new InMemoryNonceStore(),
    now: NOW
  });
  assert.equal(again.ok, true);
});

test('registry says kyc_passed=false even though signed event claims true -> REJECT', () => {
  const world = makeWorld();
  markEligible(world.registry, ALICE_HASH, { kyc_passed: false, mainnet_migrated: true });
  const signed = acceptedEvent(world);
  const result = verifySignedEvent(signed, {
    registry: world.registry,
    nonceStore: new InMemoryNonceStore(),
    now: NOW
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, 'INELIGIBLE_USER');
});

test('registry says mainnet_migrated=false even though signed event claims true -> REJECT', () => {
  const world = makeWorld();
  markEligible(world.registry, ALICE_HASH, { kyc_passed: true, mainnet_migrated: false });
  const signed = acceptedEvent(world);
  const result = verifySignedEvent(signed, {
    registry: world.registry,
    nonceStore: new InMemoryNonceStore(),
    now: NOW
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, 'INELIGIBLE_USER');
});
