import { TIMESTAMP_WINDOW_MS } from './constants.js';
import { hashUid, newEvent, signEvent } from './events.js';
import { generateKeyPair } from './keys.js';
import { InMemoryNonceStore } from './nonces.js';
import { createRegistry, registerApp, registerKey, revokeKey, markEligible } from './registry.js';
import { verifySignedEvent } from './verify.js';

const NOW = 1755860000000;

// Fixed material so every artifact derived from this suite — keys, signatures,
// committed vectors — is byte-for-byte reproducible on every machine.
const CURRENT_KEY_SEED = '11'.repeat(32);
const RETIRED_KEY_SEED = '22'.repeat(32);
const EVIL_KEY_SEED = '33'.repeat(32);
export const SUITE_UID_SECRET = 'pep-reference-uid-secret-v1';

export const SUITE_NOW = NOW;
const ALICE_HASH = hashUid('alice', SUITE_UID_SECRET);

export function makeWorld() {
  const registry = createRegistry();
  registerApp(registry, 'demo-app');
  registerApp(registry, 'evil-app');

  const currentKey = generateKeyPair({ seed: CURRENT_KEY_SEED });
  const retiredKey = generateKeyPair({ seed: RETIRED_KEY_SEED });
  const evilKey = generateKeyPair({ seed: EVIL_KEY_SEED });

  registerKey(registry, 'demo-app', 'k-2026-active', currentKey.public_key_pem, SUITE_NOW);
  registerKey(registry, 'demo-app', 'k-2025-retired', retiredKey.public_key_pem, SUITE_NOW);
  revokeKey(registry, 'demo-app', 'k-2025-retired');
  registerKey(registry, 'evil-app', 'k-evil', evilKey.public_key_pem, SUITE_NOW);

  markEligible(registry, ALICE_HASH);

  return { registry, currentKey, retiredKey, evilKey, uidSecret: SUITE_UID_SECRET };
}

function validSignedEvent(world, overrides = {}, eventOpts = {}) {
  const event = newEvent({
    app_id: 'demo-app',
    key_id: 'k-2026-active',
    action_class: 'A',
    action_id: 'complete_transaction',
    weight: 50,
    pioneer_uid: 'unused-because-hash-overridden',
    uidSecret: world.uidSecret,
    now: NOW,
    nonce: 'ab'.repeat(16),
    ...eventOpts
  });
  Object.assign(event, overrides);
  return signEvent(event, world.currentKey.private_key_pem);
}

function tamperBase64(signature) {
  const flipped = signature[0] === 'A' ? 'B' : 'A';
  return flipped + signature.slice(1);
}

export const ATTACKS = [
  {
    name: '01_replay_attack',
    description: 'exact duplicate of an already-accepted event is resubmitted',
    expected_code: 'REPLAY_DETECTED',
    precondition_verify_once: true,
    build(world) {
      const store = new InMemoryNonceStore();
      const signed = validSignedEvent(world, { pioneer_uid_hash: ALICE_HASH });
      const first = verifySignedEvent(signed, { registry: world.registry, nonceStore: store, now: NOW });
      if (!first.ok) throw new Error('precondition failed: baseline event should be accepted');
      return { event: signed, nonceStore: store };
    }
  },
  {
    name: '02_nonce_reuse',
    description: 'different payload reuses a previously accepted nonce',
    expected_code: 'REPLAY_DETECTED',
    precondition_verify_once: true,
    build(world) {
      const store = new InMemoryNonceStore();
      const signed = validSignedEvent(world, { pioneer_uid_hash: ALICE_HASH });
      verifySignedEvent(signed, { registry: world.registry, nonceStore: store, now: NOW });
      const clone = { ...signed, action_id: 'rate_product' };
      const resigned = signEvent(clone, world.currentKey.private_key_pem);
      return { event: resigned, nonceStore: store };
    }
  },
  {
    name: '03_invalid_signature',
    description: 'signature bytes are corrupted after signing',
    expected_code: 'INVALID_SIGNATURE',
    build(world) {
      const signed = validSignedEvent(world, { pioneer_uid_hash: ALICE_HASH });
      signed.signature = tamperBase64(signed.signature);
      return { event: signed };
    }
  },
  {
    name: '04_payload_mutation_weight',
    description: 'weight field edited after signing',
    expected_code: 'INVALID_SIGNATURE',
    build(world) {
      const signed = validSignedEvent(world, { pioneer_uid_hash: ALICE_HASH });
      signed.weight += 1;
      return { event: signed };
    }
  },
  {
    name: '05_payload_mutation_user',
    description: 'pioneer identity swapped after signing',
    expected_code: 'INVALID_SIGNATURE',
    build(world) {
      const signed = validSignedEvent(world, { pioneer_uid_hash: ALICE_HASH });
      signed.pioneer_uid_hash = hashUid('mallory', world.uidSecret);
      return { event: signed };
    }
  },
  {
    name: '06_timestamp_expired',
    description: 'event timestamp outside the acceptance window (too old)',
    expected_code: 'TIMESTAMP_EXPIRED',
    build(world) {
      const signed = validSignedEvent(world, { pioneer_uid_hash: ALICE_HASH }, { now: NOW - TIMESTAMP_WINDOW_MS - 1000 });
      return { event: signed };
    }
  },
  {
    name: '07_timestamp_future',
    description: 'event timestamp beyond the allowed future skew',
    expected_code: 'TIMESTAMP_IN_FUTURE',
    build(world) {
      const signed = validSignedEvent(world, { pioneer_uid_hash: ALICE_HASH }, { now: NOW + TIMESTAMP_WINDOW_MS * 2 });
      return { event: signed };
    }
  },
  {
    name: '08_weight_inflation',
    description: 'correctly signed event exceeds its class ceiling (misbehaving backend)',
    expected_code: 'WEIGHT_OVERFLOW',
    build(world) {
      const signed = validSignedEvent(world, { pioneer_uid_hash: ALICE_HASH }, { weight: 101 });
      return { event: signed };
    }
  },
  {
    name: '09_unknown_app',
    description: 'app_id never registered in the launchpad registry',
    expected_code: 'UNKNOWN_APP',
    build(world) {
      const signed = validSignedEvent(world, { pioneer_uid_hash: ALICE_HASH }, { app_id: 'ghost-app' });
      return { event: signed };
    }
  },
  {
    name: '10_revoked_key',
    description: 'signature produced by a rotated-out (revoked) backend key',
    expected_code: 'REVOKED_KEY',
    build(world) {
      const event = newEvent({
        app_id: 'demo-app',
        key_id: 'k-2025-retired',
        action_class: 'A',
        action_id: 'complete_transaction',
        weight: 50,
        pioneer_uid: 'unused-because-hash-overridden',
        uidSecret: world.uidSecret,
        now: NOW,
        nonce: 'ab'.repeat(16)
      });
      event.pioneer_uid_hash = ALICE_HASH;
      return { event: signEvent(event, world.retiredKey.private_key_pem) };
    }
  },
  {
    name: '11_cross_app_forgery',
    description: 'valid key of another app signs this app\u2019s event',
    expected_code: 'INVALID_SIGNATURE',
    build(world) {
      const event = newEvent({
        app_id: 'demo-app',
        key_id: 'k-2026-active',
        action_class: 'A',
        action_id: 'complete_transaction',
        weight: 50,
        pioneer_uid: 'unused-because-hash-overridden',
        uidSecret: world.uidSecret,
        now: NOW,
        nonce: 'ab'.repeat(16)
      });
      event.pioneer_uid_hash = ALICE_HASH;
      return { event: signEvent(event, world.evilKey.private_key_pem) };
    }
  },
  {
    name: '12_missing_field',
    description: 'required field removed from the envelope',
    expected_code: 'SCHEMA',
    build(world) {
      const signed = validSignedEvent(world, { pioneer_uid_hash: ALICE_HASH });
      delete signed.action_id;
      return { event: signed };
    }
  },
  {
    name: '13_unknown_field_injection',
    description: 'unexpected field injected into the closed schema',
    expected_code: 'SCHEMA',
    build(world) {
      const signed = validSignedEvent(world, { pioneer_uid_hash: ALICE_HASH });
      signed.admin_override = true;
      return { event: signed };
    }
  },
  {
    name: '14_unsupported_version',
    description: 'future spec version submitted against v1 verifier',
    expected_code: 'SCHEMA',
    build(world) {
      const signed = validSignedEvent(world, { pioneer_uid_hash: ALICE_HASH });
      signed.v = 99;
      return { event: signed };
    }
  },
  {
    name: '15_ineligible_user',
    description: 'KYC flag false inside the signed eligibility block',
    expected_code: 'INELIGIBLE_USER',
    build(world) {
      const signed = validSignedEvent(world, { pioneer_uid_hash: ALICE_HASH }, { kyc_passed: false });
      return { event: signed };
    }
  },
  {
    name: '16_unknown_key_claim',
    description: 'envelope claims a key_id that does not exist for the app',
    expected_code: 'UNKNOWN_KEY',
    build(world) {
      const event = newEvent({
        app_id: 'demo-app',
        key_id: 'k-fake',
        action_class: 'A',
        action_id: 'complete_transaction',
        weight: 50,
        pioneer_uid: 'unused-because-hash-overridden',
        uidSecret: world.uidSecret,
        now: NOW,
        nonce: 'ab'.repeat(16)
      });
      event.pioneer_uid_hash = ALICE_HASH;
      return { event: signEvent(event, world.currentKey.private_key_pem) };
    }
  },
  {
    name: '17_registry_kyc_false',
    description: 'signed event claims KYC passed but launchpad registry says kyc_passed=false',
    expected_code: 'INELIGIBLE_USER',
    build(world) {
      markEligible(world.registry, ALICE_HASH, { kyc_passed: false, mainnet_migrated: true });
      return { event: validSignedEvent(world) };
    }
  },
  {
    name: '18_registry_mainnet_false',
    description: 'signed event claims mainnet migration but launchpad registry says mainnet_migrated=false',
    expected_code: 'INELIGIBLE_USER',
    build(world) {
      markEligible(world.registry, ALICE_HASH, { kyc_passed: true, mainnet_migrated: false });
      return { event: validSignedEvent(world) };
    }
  },
  {
    name: '19_unregistered_pioneer',
    description: 'schema-valid pioneer hash absent from the launchpad eligibility registry entirely',
    expected_code: 'INELIGIBLE_USER',
    build(world) {
      return { event: validSignedEvent(world, { pioneer_uid_hash: hashUid('stranger', world.uidSecret) }) };
    }
  },
  {
    name: '20_prototype_key_app',
    description: 'app_id set to an inherited object-prototype property name ("constructor") to probe unsafe registry lookups',
    expected_code: 'UNKNOWN_APP',
    build(world) {
      const event = newEvent({
        app_id: 'constructor',
        key_id: 'k-2026-active',
        action_class: 'A',
        action_id: 'complete_transaction',
        weight: 50,
        pioneer_uid: 'unused-because-hash-overridden',
        uidSecret: world.uidSecret,
        now: NOW,
        nonce: 'ab'.repeat(16)
      });
      event.pioneer_uid_hash = ALICE_HASH;
      return { event: signEvent(event, world.currentKey.private_key_pem) };
    }
  }
];

export function runAttackSuite() {
  return ATTACKS.map((attack) => {
    const world = makeWorld();
    const { event, nonceStore } = attack.build(world);
    const result = verifySignedEvent(event, {
      registry: world.registry,
      nonceStore: nonceStore ?? new InMemoryNonceStore(),
      now: NOW
    });
    const rejected = !result.ok && (!attack.expected_code || result.code === attack.expected_code);
    return {
      attack: attack.name,
      description: attack.description,
      expected_code: attack.expected_code,
      actual_code: result.ok ? null : result.code,
      rejected
    };
  });
}

export function formatAttackReport(results) {
  const lines = [];
  for (const r of results) {
    const verdict = r.rejected ? 'REJECTED' : '!!! ACCEPTED !!!';
    const code = r.actual_code ? ` [${r.actual_code}]` : '';
    lines.push(`${r.rejected ? 'PASS' : 'FAIL'}  ${verdict.padEnd(18)}${r.attack.padEnd(30)}${code}`);
  }
  const rejectedCount = results.filter((r) => r.rejected).length;
  lines.push('');
  lines.push(`RESULT: ${rejectedCount}/${results.length} attacks rejected`);
  return lines.join('\n');
}
