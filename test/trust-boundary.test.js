import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeWorld } from '../src/attacks.js';
import { newEvent, signEvent } from '../src/events.js';
import { InMemoryNonceStore } from '../src/nonces.js';
import { verifySignedEvent } from '../src/verify.js';

const NOW = 1755860000000;
const ALICE_HASH = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

function signedClaim(world, { action_class = 'C', weight = 1, action_id = 'open_screen' } = {}) {
  const event = newEvent({
    app_id: 'demo-app',
    key_id: 'k-2026-active',
    action_class,
    action_id,
    weight,
    pioneer_uid: 'x',
    now: NOW
  });
  event.pioneer_uid_hash = ALICE_HASH;
  return signEvent(event, world.currentKey.private_key_pem);
}

test('TRUST BOUNDARY: a correctly-signed false claim within ceilings is accepted BY DESIGN', () => {
  const world = makeWorld();
  const lie = signedClaim(world, { action_class: 'A', weight: 100, action_id: 'never_happened_action' });

  const result = verifySignedEvent(lie, {
    registry: world.registry,
    nonceStore: new InMemoryNonceStore(),
    now: NOW
  });

  assert.equal(result.ok, true, 'PEP verifies AUTHENTICITY of issuer claims, not their TRUTHFULNESS. See SECURITY.md #trust-boundary.');
});

test('TRUST BOUNDARY: the blast radius of a lying issuer is capped by class ceilings', () => {
  const world = makeWorld();
  const inflatedLie = signedClaim(world, { action_class: 'C', weight: 999999 });

  const result = verifySignedEvent(inflatedLie, {
    registry: world.registry,
    nonceStore: new InMemoryNonceStore(),
    now: NOW
  });

  assert.equal(result.ok, false);
  assert.equal(result.code, 'WEIGHT_OVERFLOW');
});
