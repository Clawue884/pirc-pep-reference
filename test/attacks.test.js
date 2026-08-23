import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ATTACKS, runAttackSuite } from '../src/attacks.js';

test('attack suite: every adversarial scenario is rejected with its expected error code', () => {
  const results = runAttackSuite();
  assert.equal(results.length, ATTACKS.length);
  for (const r of results) {
    assert.ok(r.rejected, `attack ${r.attack} was NOT rejected (expected ${r.expected_code}, got ${r.actual_code ?? 'ACCEPT'})`);
    assert.equal(r.actual_code, r.expected_code, `attack ${r.attack} rejected with wrong code`);
  }
});

test('suite covers the documented adversarial matrix', () => {
  const names = ATTACKS.map((a) => a.name);
  for (const expected of [
    '01_replay_attack',
    '02_nonce_reuse',
    '03_invalid_signature',
    '04_payload_mutation_weight',
    '05_payload_mutation_user',
    '06_timestamp_expired',
    '07_timestamp_future',
    '08_weight_inflation',
    '09_unknown_app',
    '10_revoked_key',
    '11_cross_app_forgery',
    '12_missing_field',
    '13_unknown_field_injection',
    '14_unsupported_version',
    '15_ineligible_user',
    '16_unknown_key_claim',
    '17_registry_kyc_false',
    '18_registry_mainnet_false',
    '19_unregistered_pioneer'
      {
    name: '20_empty_nonce',
    description: 'nonce is present but malformed and empty',
    expected_code: 'SCHEMA',
    build(world) {
      const signed = validSignedEvent(
        world,
        { pioneer_uid_hash: ALICE_HASH }
      );

      signed.nonce = '';

      return { event: signed };
    }
  },

  {
    name: '21_uppercase_nonce',
    description: 'nonce uses uppercase hexadecimal characters',
    expected_code: 'SCHEMA',
    build(world) {
      const signed = validSignedEvent(
        world,
        { pioneer_uid_hash: ALICE_HASH }
      );

      signed.nonce = signed.nonce.toUpperCase();

      return { event: signed };
    }
  },

  {
    name: '22_fractional_weight',
    description: 'weight is changed from integer to floating point',
    expected_code: 'SCHEMA',
    build(world) {
      const signed = validSignedEvent(
        world,
        { pioneer_uid_hash: ALICE_HASH }
      );

      signed.weight = 50.5;

      return { event: signed };
    }
  },

  {
    name: '23_negative_weight',
    description: 'weight is negative',
    expected_code: 'SCHEMA',
    build(world) {
      const signed = validSignedEvent(
        world,
        { pioneer_uid_hash: ALICE_HASH }
      );

      signed.weight = -1;

      return { event: signed };
    }
  },

  {
    name: '24_extra_eligibility_field',
    description: 'eligibility object receives an unauthorized field',
    expected_code: 'SCHEMA',
    build(world) {
      const signed = validSignedEvent(
        world,
        { pioneer_uid_hash: ALICE_HASH }
      );

      signed.eligibility.admin = true;

      return { event: signed };
    }
  },

  {
    name: '25_timestamp_string',
    description: 'timestamp is represented as a string instead of an integer',
    expected_code: 'SCHEMA',
    build(world) {
      const signed = validSignedEvent(
        world,
        { pioneer_uid_hash: ALICE_HASH }
      );

      signed.timestamp = String(NOW);

      return { event: signed };
    }
  },
  ]) {
    assert.ok(names.includes(expected), `missing attack scenario: ${expected}`);
  }
});
