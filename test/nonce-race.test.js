import test from 'node:test';
import assert from 'node:assert/strict';

import {
  InMemoryNonceStore,
  FileNonceStore
} from '../src/nonces.js';

import {
  makeWorld,
  SUITE_NOW
} from './attacks.test.js';

import {
  newEvent,
  signEvent
} from '../src/events.js';

import {
  verifySignedEvent
} from '../src/verify.js';

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const ALICE_HASH =
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

function makeSignedEvent(world) {
  const event = newEvent({
    app_id: 'demo-app',
    key_id: 'k-2026-active',
    action_class: 'A',
    action_id: 'complete_transaction',
    weight: 50,
    pioneer_uid: 'unused',
    now: SUITE_NOW
  });

  event.pioneer_uid_hash = ALICE_HASH;

  return signEvent(
    event,
    world.currentKey.private_key_pem
  );
}

test('InMemoryNonceStore.claim accepts a nonce exactly once', () => {
  const store = new InMemoryNonceStore();

  assert.equal(
    store.claim('demo-app:nonce-1'),
    true
  );

  assert.equal(
    store.claim('demo-app:nonce-1'),
    false
  );

  assert.equal(store.size(), 1);
});

test('replay is rejected when the same signed event is verified twice', () => {
  const world = makeWorld();
  const store = new InMemoryNonceStore();
  const event = makeSignedEvent(world);

  const first = verifySignedEvent(
    event,
    {
      registry: world.registry,
      nonceStore: store,
      now: SUITE_NOW
    }
  );

  const second = verifySignedEvent(
    event,
    {
      registry: world.registry,
      nonceStore: store,
      now: SUITE_NOW
    }
  );

  assert.equal(first.ok, true);
  assert.equal(second.ok, false);
  assert.equal(second.code, 'REPLAY_DETECTED');

  assert.equal(store.size(), 1);
});

test('many synchronous claims for one nonce produce exactly one winner', () => {
  const store = new InMemoryNonceStore();

  const results = [];

  for (let i = 0; i < 1000; i += 1) {
    results.push(
      store.claim('demo-app:race-nonce')
    );
  }

  const winners =
    results.filter(Boolean).length;

  assert.equal(winners, 1);
  assert.equal(store.size(), 1);
});

test('different apps may independently claim the same nonce value', () => {
  const store = new InMemoryNonceStore();

  assert.equal(
    store.claim('app-a:same-nonce'),
    true
  );

  assert.equal(
    store.claim('app-b:same-nonce'),
    true
  );

  assert.equal(store.size(), 2);
});

test('FileNonceStore persists claimed nonces', () => {
  const dir = fs.mkdtempSync(
    path.join(os.tmpdir(), 'pep-nonce-test-')
  );

  const file = path.join(
    dir,
    'nonces.jsonl'
  );

  try {
    const first = new FileNonceStore(file);

    assert.equal(
      first.claim('demo-app:persistent'),
      true
    );

    const second = new FileNonceStore(file);

    assert.equal(
      second.has('demo-app:persistent'),
      true
    );

    assert.equal(
      second.claim('demo-app:persistent'),
      false
    );
  } finally {
    fs.rmSync(dir, {
      recursive: true,
      force: true
    });
  }
});
