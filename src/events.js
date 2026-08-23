import crypto from 'node:crypto';
import { canonicalize } from './canonical.js';
import { DOMAIN, SPEC_VERSION } from './constants.js';
import { randomNonce, signMessage } from './keys.js';

// Keyed pseudonymization: pioneer_uid never leaves the backend, and what does
// leave is an HMAC-SHA256 over a server-side secret — so low-entropy UIDs are
// immune to dictionary recovery and the same person hashes differently in
// deployments (or apps) that use different secrets. The version prefix allows
// secret rotation without re-hashing historical ambiguity.
export function hashUid(uid, secret, { version = 'h1' } = {}) {
  if (typeof secret !== 'string' || secret.length < 16) {
    throw new TypeError('hashUid requires a server-side secret of at least 16 characters');
  }
  if (typeof uid !== 'string') {
    throw new TypeError('uid must be a string');
  }
  const mac = crypto.createHmac('sha256', secret).update(uid.normalize('NFC'), 'utf8').digest('base64url');
  return `${version}:${mac}`;
}

export function newEvent({ app_id, key_id, action_class, action_id, weight, pioneer_uid, uidSecret, now = Date.now(), nonce, kyc_passed = true, mainnet_migrated = true }) {
  return {
    v: SPEC_VERSION,
    app_id,
    key_id,
    action_class,
    action_id,
    weight,
    timestamp: now,
    // Supply `nonce` to get fully deterministic, byte-for-byte reproducible
    // events (required for committed test vectors); production callers should
    // let it default to a fresh random value.
    nonce: nonce !== undefined ? nonce : randomNonce(),
    pioneer_uid_hash: hashUid(pioneer_uid, uidSecret),
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
