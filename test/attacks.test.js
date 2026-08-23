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
    '19_unregistered_pioneer',
    '20_prototype_key_app'
  ]) {
    assert.ok(names.includes(expected), `missing attack scenario: ${expected}`);
  }
});
