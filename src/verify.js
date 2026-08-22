import { canonicalize, CanonicalError } from './canonical.js';
import {
  DOMAIN,
  ERROR_CODES,
  TIMESTAMP_WINDOW_MS,
  WEIGHT_CEILINGS
} from './constants.js';
import { verifySignature } from './keys.js';
import { resolveKey, getEligibilityRecord } from './registry.js';
import { schemaError } from './schema.js';

/**
 * PEP/1 Trust Boundary
 *
 * A successful verification proves:
 * - schema validity
 * - registered application
 * - active signing key
 * - canonical message integrity
 * - valid Ed25519 signature
 * - timestamp freshness
 * - bounded weight
 * - registry-backed eligibility
 * - nonce non-replay
 *
 * It DOES NOT prove that the issuer's underlying claim is truthful.
 */

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function decodeEd25519Signature(value) {
  if (typeof value !== 'string') {
    return null;
  }

  /*
   * Ed25519 signatures are exactly 64 bytes.
   *
   * Buffer.from(str, 'base64') is intentionally permissive, so
   * decoding alone is not sufficient for protocol validation.
   */
  if (value.length === 0 || value.length % 4 !== 0) {
    return null;
  }

  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    return null;
  }

  /*
   * Padding is only valid at the end.
   */
  const firstPadding = value.indexOf('=');
  if (firstPadding !== -1 && firstPadding < value.length - 2) {
    return null;
  }

  let decoded;

  try {
    decoded = Buffer.from(value, 'base64');
  } catch {
    return null;
  }

  if (decoded.length !== 64) {
    return null;
  }

  /*
   * Canonical base64 representation check.
   * Re-encoding must produce the exact original string.
   */
  if (decoded.toString('base64') !== value) {
    return null;
  }

  return decoded;
}

function canonicalMessage(event) {
  if (!isPlainObject(event)) {
    throw new CanonicalError('event must be a plain object');
  }

  const body = { ...event };
  delete body.signature;

  const c1 = canonicalize(body);
  const c2 = canonicalize(JSON.parse(c1));

  if (c1 !== c2) {
    throw new CanonicalError('canonicalization is not stable');
  }

  return {
    canonical: c1,
    bytes: Buffer.from(`${DOMAIN}\n${c1}`, 'utf8')
  };
}

export function signingBytesFromEvent(event) {
  return canonicalMessage(event).bytes;
}

export function verifySignedEvent(
  event,
  {
    registry,
    nonceStore,
    now = Date.now()
  }
) {
  const checks = [];

  const record = (check, pass) => {
    checks.push({ check, pass });
  };

  const reject = (check, code) => {
    record(check, false);

    return {
      ok: false,
      code,
      checks
    };
  };

  /*
   * Verification context validation.
   *
   * These are programmer/configuration errors, not attacker-controlled
   * protocol failures, therefore they throw instead of returning a
   * protocol error code.
   */
  if (
    !nonceStore ||
    typeof nonceStore.has !== 'function' ||
    typeof nonceStore.add !== 'function'
  ) {
    throw new TypeError(
      'nonceStore is required (use InMemoryNonceStore or FileNonceStore)'
    );
  }

  if (!Number.isSafeInteger(now)) {
    throw new TypeError('now must be a safe integer');
  }

  /*
   * ---------------------------------------------------------------
   * 1. SCHEMA
   * ---------------------------------------------------------------
   */
  if (!isPlainObject(event)) {
    return reject('SCHEMA', ERROR_CODES.SCHEMA);
  }

  const structural = schemaError(event);

  if (structural !== null) {
    return reject('SCHEMA', ERROR_CODES.SCHEMA);
  }

  record('SCHEMA', true);

  /*
   * ---------------------------------------------------------------
   * 2. APP_KNOWN
   * ---------------------------------------------------------------
   *
   * Own-property lookup prevents prototype-chain resolution.
   */
  if (
    !registry ||
    !isPlainObject(registry.apps) ||
    !hasOwn(registry.apps, event.app_id)
  ) {
    return reject('APP_KNOWN', ERROR_CODES.UNKNOWN_APP);
  }

  record('APP_KNOWN', true);

  /*
   * ---------------------------------------------------------------
   * 3. KEY_ACTIVE
   * ---------------------------------------------------------------
   */
  const keyRecord = resolveKey(
    registry,
    event.app_id,
    event.key_id
  );

  if (!keyRecord) {
    return reject('KEY_ACTIVE', ERROR_CODES.UNKNOWN_KEY);
  }

  if (keyRecord.status !== 'active') {
    return reject('KEY_ACTIVE', ERROR_CODES.REVOKED_KEY);
  }

  /*
   * Explicit trust-boundary check:
   * the key must belong to the application being verified.
   *
   * This is defensive even if resolveKey() already guarantees it.
   */
  if (
    hasOwn(keyRecord, 'app_id') &&
    keyRecord.app_id !== event.app_id
  ) {
    return reject('KEY_ACTIVE', ERROR_CODES.UNKNOWN_KEY);
  }

  record('KEY_ACTIVE', true);

  /*
   * ---------------------------------------------------------------
   * 4. CANONICALIZATION
   * ---------------------------------------------------------------
   */
  let msgBytes;

  try {
    const result = canonicalMessage(event);
    msgBytes = result.bytes;
  } catch (err) {
    if (
      err instanceof CanonicalError ||
      err instanceof SyntaxError
    ) {
      return reject(
        'CANONICALIZATION',
        ERROR_CODES.CANONICALIZATION
      );
    }

    throw err;
  }

  record('CANONICALIZATION', true);

  /*
   * ---------------------------------------------------------------
   * 5. SIGNATURE
   * ---------------------------------------------------------------
   */
  const sigBytes = decodeEd25519Signature(event.signature);

  if (sigBytes === null) {
    return reject(
      'SIGNATURE',
      ERROR_CODES.INVALID_SIGNATURE
    );
  }

  let validSignature = false;

  try {
    validSignature = verifySignature(
      keyRecord.public_key_pem,
      msgBytes,
      sigBytes
    );
  } catch {
    validSignature = false;
  }

  if (!validSignature) {
    return reject(
      'SIGNATURE',
      ERROR_CODES.INVALID_SIGNATURE
    );
  }

  record('SIGNATURE', true);

  /*
   * ---------------------------------------------------------------
   * 6. TIMESTAMP_FRESHNESS
   * ---------------------------------------------------------------
   */
  const delta = now - event.timestamp;

  if (delta < -TIMESTAMP_WINDOW_MS) {
    return reject(
      'TIMESTAMP_FRESHNESS',
      ERROR_CODES.TIMESTAMP_IN_FUTURE
    );
  }

  if (delta > TIMESTAMP_WINDOW_MS) {
    return reject(
      'TIMESTAMP_FRESHNESS',
      ERROR_CODES.TIMESTAMP_EXPIRED
    );
  }

  record('TIMESTAMP_FRESHNESS', true);

  /*
   * ---------------------------------------------------------------
   * 7. WEIGHT_BOUND
   * ---------------------------------------------------------------
   *
   * The signature authenticates the weight, but does not authorize
   * weights beyond the protocol ceiling.
   */
  const ceiling = WEIGHT_CEILINGS[event.action_class];

  if (
    !Number.isSafeInteger(ceiling) ||
    event.weight > ceiling
  ) {
    return reject(
      'WEIGHT_BOUND',
      ERROR_CODES.WEIGHT_OVERFLOW
    );
  }

  record('WEIGHT_BOUND', true);

  /*
   * ---------------------------------------------------------------
   * 8. ELIGIBILITY
   * ---------------------------------------------------------------
   *
   * Self-declared eligibility is NEVER treated as authoritative.
   * The launchpad-controlled registry remains the trust anchor.
   */
  const elig = event.eligibility;

  const selfDeclared =
    elig?.kyc_passed === true &&
    elig?.mainnet_migrated === true;

  const eligRecord = getEligibilityRecord(
    registry,
    event.pioneer_uid_hash
  );

  const registryConfirmed =
    eligRecord !== null &&
    eligRecord.kyc_passed === true &&
    eligRecord.mainnet_migrated === true;

  if (!selfDeclared || !registryConfirmed) {
    return reject(
      'ELIGIBILITY',
      ERROR_CODES.INELIGIBLE_USER
    );
  }

  record('ELIGIBILITY', true);

  /*
   * ---------------------------------------------------------------
   * 9. NONCE_REPLAY
   * ---------------------------------------------------------------
   *
   * IMPORTANT:
   * The current nonce-store interface exposes has() + add().
   * Therefore atomicity cannot be guaranteed by this verifier alone.
   *
   * Implementations requiring concurrent verification SHOULD provide
   * an atomic check-and-add primitive in a future conformance profile.
   */
  const nonceKey = `${event.app_id}:${event.nonce}`;

  if (nonceStore.has(nonceKey)) {
    return reject(
      'NONCE_REPLAY',
      ERROR_CODES.REPLAY_DETECTED
    );
  }

  nonceStore.add(nonceKey);

  record('NONCE_REPLAY', true);

  /*
   * ---------------------------------------------------------------
   * SUCCESS
   * ---------------------------------------------------------------
   *
   * `ok: true` means the event satisfies PEP/1 protocol validation.
   * It does NOT mean the underlying real-world claim is proven true.
   */
  return {
    ok: true,
    code: null,
    checks,
    trust: {
      authenticated: true,
      eligible: true,
      bounded: true,
      non_replayed: true,
      truthfulness_proven: false,
      economic_value_proven: false
    }
  };
}
