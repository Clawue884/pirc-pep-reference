import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { makeWorld, SUITE_UID_SECRET, SUITE_NOW } from '../src/attacks.js';
import { canonicalize, CanonicalError } from '../src/canonical.js';
import { hashUid, newEvent, signEvent } from '../src/events.js';
import { generateKeyPair, publicKeyFingerprint } from '../src/keys.js';
import { FileNonceStore, InMemoryNonceStore } from '../src/nonces.js';
import { createRegistry, registerApp, registerKey, markEligible } from '../src/registry.js';
import { verifySignedEvent } from '../src/verify.js';

const NOW = SUITE_NOW;
const ALICE = hashUid('alice', SUITE_UID_SECRET);

function signedEvent(world, overrides = {}) {
  const event = newEvent({
    app_id: 'demo-app',
    key_id: 'k-2026-active',
    action_class: 'A',
    action_id: 'complete_transaction',
    weight: 50,
    pioneer_uid: 'x',
    uidSecret: world.uidSecret,
    now: NOW
  });
  Object.assign(event, { pioneer_uid_hash: ALICE }, overrides);
  return signEvent(event, world.currentKey.private_key_pem);
}

// --- deterministic key material -------------------------------------------

test('seeded Ed25519 keypair reproduces RFC 8032 test-vector-1 public key', () => {
  const seed = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
  const expectedPub = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
  const kp = generateKeyPair({ seed });
  assert.equal(publicKeyFingerprint(kp.public_key_pem), expectedPub);
});

test('makeWorld() is fully reproducible: identical keys across independent runs', () => {
  const w1 = makeWorld();
  const w2 = makeWorld();
  assert.equal(w1.currentKey.private_key_pem, w2.currentKey.private_key_pem);
  assert.equal(w1.currentKey.public_key_pem, w2.currentKey.public_key_pem);
  const e1 = signEvent(
    { v: 1, app_id: 'demo-app', key_id: 'k', action_class: 'C', action_id: 'x', weight: 1, timestamp: NOW, nonce: 'ab'.repeat(16), pioneer_uid_hash: w1.registry.eligible_users[Object.keys(w1.registry.eligible_users)[0]] ? Object.keys(w1.registry.eligible_users)[0] : '', eligibility: { kyc_passed: true, mainnet_migrated: true } },
    w1.currentKey.private_key_pem
  );
  const e2 = signEvent(JSON.parse(JSON.stringify(e1)), w2.currentKey.private_key_pem);
  assert.equal(e1.signature, e2.signature);
});

test('hashUid is a versioned HMAC: deterministic per secret, distinct across secrets', () => {
  const h1 = hashUid('alice', SUITE_UID_SECRET);
  assert.match(h1, /^h1:[A-Za-z0-9_-]{43}$/);
  assert.equal(h1, hashUid('alice', SUITE_UID_SECRET));
  assert.notEqual(h1, hashUid('alice', 'another-secret-0123456789abcdef'));
  assert.notEqual(hashUid('bob', SUITE_UID_SECRET), h1);
});

test('hashUid rejects missing or short secrets and normalizes unicode form', () => {
  assert.throws(() => hashUid('alice'), TypeError);
  assert.throws(() => hashUid('alice', 'short'), TypeError);
  const nfc = hashUid('caf\u00e9', SUITE_UID_SECRET);
  const nfd = hashUid('cafe\u0301', SUITE_UID_SECRET);
  assert.equal(nfc, nfd);
});

// --- atomic nonce claiming --------------------------------------------------

test('claimIfAbsent is test-and-set: exactly one of two claims wins', () => {
  const store = new InMemoryNonceStore();
  assert.equal(store.claimIfAbsent('demo-app:' + 'ab'.repeat(16)), true);
  assert.equal(store.claimIfAbsent('demo-app:' + 'ab'.repeat(16)), false);
});

test('failed verification never burns the nonce even under claim semantics', () => {
  const world = makeWorld();
  const store = new InMemoryNonceStore();
  const signed = signedEvent(world);
  const first = verifySignedEvent(signed, {
    registry: { version: 1, apps: {}, eligible_users: {} },
    nonceStore: store,
    now: NOW
  });
  assert.equal(first.code, 'UNKNOWN_APP');
  const second = verifySignedEvent(signed, { registry: world.registry, nonceStore: store, now: NOW });
  assert.equal(second.ok, true);
});

test('two verifier instances sharing one durable store cannot double-accept', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pep-hard-'));
  const file = path.join(dir, 'nonces.log');
  const verifierA = new FileNonceStore(file);
  const verifierB = new FileNonceStore(file);

  assert.equal(verifierA.claimIfAbsent('demo-app:' + 'cd'.repeat(16)), true);
  assert.equal(verifierB.claimIfAbsent('demo-app:' + 'cd'.repeat(16)), false);

  fs.rmSync(dir, { recursive: true, force: true });
});

test('claims survive a simulated crash (fresh instance reads fsynced log)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pep-hard-'));
  const file = path.join(dir, 'nonces.log');

  const beforeCrash = new FileNonceStore(file);
  beforeCrash.claimIfAbsent('demo-app:' + 'ef'.repeat(16));

  const afterCrash = new FileNonceStore(file);
  assert.equal(afterCrash.claimIfAbsent('demo-app:' + 'ef'.repeat(16)), false);

  fs.rmSync(dir, { recursive: true, force: true });
});

test('corrupt log lines are skipped and counted instead of crashing', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pep-hard-'));
  const file = path.join(dir, 'nonces.log');
  fs.writeFileSync(
    file,
    'demo-app:' + 'aa'.repeat(16) + '\nGARBAGE-LINE\n\n',
    'utf8'
  );

  const store = new FileNonceStore(file);
  assert.equal(store.corruptLines, 1);
  assert.equal(store.has('demo-app:' + 'aa'.repeat(16)), true);

  assert.equal(store.claimIfAbsent('demo-app:' + 'bb'.repeat(16)), true);
  store.compact();

  const compacted = new FileNonceStore(file);
  assert.equal(compacted.corruptLines, 0);
  assert.deepEqual([...compacted.seen].sort(), [
    'demo-app:' + 'aa'.repeat(16),
    'demo-app:' + 'bb'.repeat(16)
  ]);

  fs.rmSync(dir, { recursive: true, force: true });
});

test('FileNonceStore refuses to persist malformed nonce keys', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pep-hard-'));
  const store = new FileNonceStore(path.join(dir, 'nonces.log'));
  assert.throws(() => store.claimIfAbsent('injection;rm-rf'), TypeError);
  fs.rmSync(dir, { recursive: true, force: true });
});

// --- prototype-pollution resistance -----------------------------------------

test('registry lookups use own-property semantics for inherited names', () => {
  const world = makeWorld();
  // Both are real Object.prototype members whose names also satisfy the
  // app_id grammar ([a-z0-9][a-z0-9-]{2,63}), so they reach the lookup itself.
  for (const name of ['constructor', 'valueof']) {
    const result = verifySignedEvent(signedEvent(world, { app_id: name }), {
      registry: createRegistry(),
      nonceStore: new InMemoryNonceStore(),
      now: NOW
    });
    assert.equal(result.code, 'UNKNOWN_APP', name);
  }
});

test('markEligible refuses prototype-dangerous keys', () => {
  const registry = createRegistry();
  assert.throws(() => markEligible(registry, '__proto__'), TypeError);
  assert.throws(() => markEligible(registry, 'constructor'), TypeError);
});

// --- resource & encoding guards ---------------------------------------------

test('canonicalizer enforces a depth cap instead of overflowing the stack', () => {
  let bomb = {};
  const root = bomb;
  for (let i = 0; i < 500; i++) {
    bomb.n = {};
    bomb = bomb.n;
  }
  assert.throws(() => canonicalize(root), CanonicalError);
});

test('canonical output is NFC-stable regardless of input normalization', () => {
  assert.equal(canonicalize('e\u0301'), canonicalize('\u00e9'));
});

test('deeply nested junk inside an unknown field hits SCHEMA before any recursion', () => {
  const world = makeWorld();
  const signed = signedEvent(world);
  let deep = {};
  const cursor = deep;
  for (let i = 0; i < 5000; i++) {
    cursor.next = {};
  }
  signed.bomb = cursor;
  const result = verifySignedEvent(signed, { registry: world.registry, nonceStore: new InMemoryNonceStore(), now: NOW });
  assert.equal(result.code, 'SCHEMA');
});

test('malformed PEM in a registry entry degrades to INVALID_SIGNATURE, never a throw', () => {
  const world = makeWorld();
  const poisoned = JSON.parse(JSON.stringify(world.registry));
  poisoned.apps['demo-app'].keys['k-2026-active'].public_key_pem =
    '-----BEGIN PUBLIC KEY-----\nGARBAGE\n-----END PUBLIC KEY-----\n';
  const result = verifySignedEvent(signedEvent(world), {
    registry: poisoned,
    nonceStore: new InMemoryNonceStore(),
    now: NOW
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, 'INVALID_SIGNATURE');
});

// --- clock manipulation -------------------------------------------------------

test('clock rollback cannot resurrect an already-accepted event', () => {
  const world = makeWorld();
  const store = new InMemoryNonceStore();
  const signed = signedEvent(world);

  const first = verifySignedEvent(signed, { registry: world.registry, nonceStore: store, now: NOW });
  assert.equal(first.ok, true);

  const replayUnderRolledBackClock = verifySignedEvent(signed, {
    registry: world.registry,
    nonceStore: store,
    now: NOW - 10 * 60 * 1000
  });
  assert.equal(replayUnderRolledBackClock.ok, false);
});

// --- protocol hygiene ----------------------------------------------------------

test('random-free world: signing the same body twice yields the same signature', () => {
  const world = makeWorld();
  const body = {
    v: 1,
    app_id: 'demo-app',
    key_id: 'k-2026-active',
    action_class: 'B',
    action_id: 'finish_lesson',
    weight: 7,
    timestamp: NOW,
    nonce: 'ab'.repeat(16),
    pioneer_uid_hash: hashUid('alice', SUITE_UID_SECRET),
    eligibility: { kyc_passed: true, mainnet_migrated: true }
  };
  const s1 = signEvent(body, world.currentKey.private_key_pem).signature;
  const s2 = signEvent(body, world.currentKey.private_key_pem).signature;
  assert.equal(s1, s2);
});
