import test from 'node:test';
import assert from 'node:assert/strict';

import {
  CHECK_ORDER,
  ERROR_CODES,
  WEIGHT_CEILINGS
} from '../src/constants.js';

import {
  ATTACKS,
  makeWorld,
  SUITE_NOW
} from './attacks.test.js';

import {
  newEvent,
  signEvent
} from '../src/events.js';

import {
  InMemoryNonceStore
} from '../src/nonces.js';

import {
  verifySignedEvent
} from '../src/verify.js';

function validEvent(world, overrides = {}) {
  const event = newEvent({
    app_id: 'demo-app',
    key_id: 'k-2026-active',
    action_class: 'A',
    action_id: 'complete_transaction',
    weight: 50,
    pioneer_uid: 'unused',
    now: SUITE_NOW
  });

  event.pioneer_uid_hash =
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

  Object.assign(event, overrides);

  return signEvent(
    event,
    world.currentKey.private_key_pem
  );
}

test('PEP/1 defines exactly nine verification stages', () => {
  assert.deepEqual(CHECK_ORDER, [
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
});

test('valid PEP/1 event passes all nine checks', () => {
  const world = makeWorld();

  const result = verifySignedEvent(
    validEvent(world),
    {
      registry: world.registry,
      nonceStore: new InMemoryNonceStore(),
      now: SUITE_NOW
    }
  );

  assert.equal(result.ok, true);
  assert.equal(result.code, null);

  assert.deepEqual(
    result.checks.map((x) => x.check),
    CHECK_ORDER
  );

  assert.ok(
    result.checks.every((x) => x.pass === true)
  );
});

test('verification failures are a prefix of the normative pipeline', () => {
  for (const attack of ATTACKS) {
    const world = makeWorld();
    const built = attack.build(world);

    const result = verifySignedEvent(
      built.event,
      {
        registry: world.registry,
        nonceStore:
          built.nonceStore ?? new InMemoryNonceStore(),
        now: SUITE_NOW
      }
    );

    assert.equal(
      result.ok,
      false,
      `${attack.name} unexpectedly passed`
    );

    const names = result.checks.map((x) => x.check);

    assert.deepEqual(
      names,
      CHECK_ORDER.slice(0, names.length),
      `${attack.name} violated verification order`
    );
  }
});

test('weight ceilings are exactly A=100, B=10, C=1', () => {
  assert.deepEqual(
    WEIGHT_CEILINGS,
    {
      A: 100,
      B: 10,
      C: 1
    }
  );
});

test('class ceiling is enforced even for a valid signature', () => {
  for (const [actionClass, ceiling] of Object.entries(WEIGHT_CEILINGS)) {
    const world = makeWorld();

    const event = validEvent(world, {
      action_class: actionClass,
      weight: ceiling + 1
    });

    const result = verifySignedEvent(
      event,
      {
        registry: world.registry,
        nonceStore: new InMemoryNonceStore(),
        now: SUITE_NOW
      }
    );

    assert.equal(result.ok, false);
    assert.equal(
      result.code,
      ERROR_CODES.WEIGHT_OVERFLOW
    );

    assert.equal(
      result.checks.at(-1).check,
      'WEIGHT_BOUND'
    );
  }
});

test('failed verification never burns the nonce', () => {
  const world = makeWorld();

  const event = validEvent(world, {
    weight: 101
  });

  const nonceKey =
    `${event.app_id}:${event.nonce}`;

  const store = new InMemoryNonceStore();

  const result = verifySignedEvent(
    event,
    {
      registry: world.registry,
      nonceStore: store,
      now: SUITE_NOW
    }
  );

  assert.equal(result.ok, false);
  assert.equal(
    result.code,
    ERROR_CODES.WEIGHT_OVERFLOW
  );

  assert.equal(
    store.has(nonceKey),
    false
  );
});

test('successful verification burns the nonce exactly once', () => {
  const world = makeWorld();
  const store = new InMemoryNonceStore();

  const event = validEvent(world);

  const first = verifySignedEvent(
    event,
    {
      registry: world.registry,
      nonceStore: store,
      now: SUITE_NOW
    }
  );

  assert.equal(first.ok, true);
  assert.equal(store.size(), 1);

  const second = verifySignedEvent(
    event,
    {
      registry: world.registry,
      nonceStore: store,
      now: SUITE_NOW
    }
  );

  assert.equal(second.ok, false);
  assert.equal(
    second.code,
    ERROR_CODES.REPLAY_DETECTED
  );

  assert.equal(store.size(), 1);
});
