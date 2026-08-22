import { canonicalize } from './canonical.js';
import { DOMAIN, SPEC_VERSION } from './constants.js';
import { randomNonce, sha256Hex, signMessage } from './keys.js';

export function hashUid(uid, salt = '') {
  return sha256Hex(salt + uid);
}

export function newEvent({ app_id, key_id, action_class, action_id, weight, pioneer_uid, now = Date.now(), kyc_passed = true, mainnet_migrated = true }) {
  return {
    v: SPEC_VERSION,
    app_id,
    key_id,
    action_class,
    action_id,
    weight,
    timestamp: now,
    nonce: randomNonce(),
    pioneer_uid_hash: hashUid(pioneer_uid),
    eligibility: { kyc_passed, mainnet_migrated }
  };
}

export function signingBytes(event) {
  const body = { ...event };
  delete body.signature;
  return Buffer.from(DOMAIN + '\n' + canonicalize(body), 'utf8');
}

export function signEvent(event, privateKeyPem) {
  const signature = signMessage(privateKeyPem, signingBytes(event)).toString('base64');
  const signed = { ...event, signature };
  return signed;
}
