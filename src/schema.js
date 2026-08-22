import { ACTION_CLASSES, SPEC_VERSION } from './constants.js';

const HEX64 = /^[0-9a-f]{64}$/;
const HEX32 = /^[0-9a-f]{32}$/;

/*
 * Exactly 64 bytes encoded as canonical Base64.
 *
 * 64 bytes -> 88 Base64 characters, ending with ==.
 */
const B64_512BIT = /^[A-Za-z0-9+/]{86}==$/;

const APP_ID = /^[a-z0-9][a-z0-9-]{2,63}$/;
const KEY_ID = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/;
const ACTION_ID = /^[a-z0-9][a-zA-Z0-9._:-]{1,127}$/;

const TOP_LEVEL_KEYS = Object.freeze([
  'v',
  'app_id',
  'key_id',
  'action_class',
  'action_id',
  'weight',
  'timestamp',
  'nonce',
  'pioneer_uid_hash',
  'eligibility',
  'signature'
]);

const TOP_LEVEL_KEY_SET = new Set(TOP_LEVEL_KEYS);

const ELIGIBILITY_KEYS = Object.freeze([
  'kyc_passed',
  'mainnet_migrated'
]);

const ELIGIBILITY_KEY_SET = new Set(ELIGIBILITY_KEYS);

function isPlainObject(value) {
  if (
    value === null ||
    typeof value !== 'object' ||
    Array.isArray(value)
  ) {
    return false;
  }

  const proto = Object.getPrototypeOf(value);

  return proto === Object.prototype || proto === null;
}

function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function exactKeys(object, expectedSet, expectedLength) {
  const keys = Object.keys(object);

  if (keys.length !== expectedLength) {
    return false;
  }

  for (const key of keys) {
    if (!expectedSet.has(key)) {
      return false;
    }
  }

  return true;
}

export function schemaError(event) {
  /*
   * ---------------------------------------------------------------
   * ROOT OBJECT
   * ---------------------------------------------------------------
   */
  if (!isPlainObject(event)) {
    return 'event must be a JSON object';
  }

  /*
   * ---------------------------------------------------------------
   * CLOSED TOP-LEVEL SCHEMA
   * ---------------------------------------------------------------
   */
  const actualKeys = Object.keys(event);

  if (actualKeys.length !== TOP_LEVEL_KEYS.length) {
    /*
     * Return a deterministic error for the first violation.
     */
    for (const key of actualKeys.sort()) {
      if (!TOP_LEVEL_KEY_SET.has(key)) {
        return `unknown field: ${key}`;
      }
    }

    for (const key of TOP_LEVEL_KEYS) {
      if (!hasOwn(event, key)) {
        return `missing field: ${key}`;
      }
    }
  }

  for (const key of actualKeys) {
    if (!TOP_LEVEL_KEY_SET.has(key)) {
      return `unknown field: ${key}`;
    }
  }

  for (const key of TOP_LEVEL_KEYS) {
    if (!hasOwn(event, key)) {
      return `missing field: ${key}`;
    }
  }

  /*
   * ---------------------------------------------------------------
   * VERSION
   * ---------------------------------------------------------------
   */
  if (event.v !== SPEC_VERSION) {
    return `unsupported spec version: ${JSON.stringify(event.v)}`;
  }

  /*
   * ---------------------------------------------------------------
   * APP ID
   * ---------------------------------------------------------------
   */
  if (
    typeof event.app_id !== 'string' ||
    !APP_ID.test(event.app_id)
  ) {
    return 'app_id must match [a-z0-9][a-z0-9-]{2,63}';
  }

  /*
   * ---------------------------------------------------------------
   * KEY ID
   * ---------------------------------------------------------------
   */
  if (
    typeof event.key_id !== 'string' ||
    !KEY_ID.test(event.key_id)
  ) {
    return 'key_id must match [a-zA-Z0-9][a-zA-Z0-9._-]{0,63}';
  }

  /*
   * ---------------------------------------------------------------
   * ACTION CLASS
   * ---------------------------------------------------------------
   */
  if (!ACTION_CLASSES.includes(event.action_class)) {
    return `action_class must be one of ${ACTION_CLASSES.join('|')}`;
  }

  /*
   * ---------------------------------------------------------------
   * ACTION ID
   * ---------------------------------------------------------------
   */
  if (
    typeof event.action_id !== 'string' ||
    !ACTION_ID.test(event.action_id)
  ) {
    return 'action_id is malformed';
  }

  /*
   * ---------------------------------------------------------------
   * WEIGHT
   * ---------------------------------------------------------------
   */
  if (
    !Number.isSafeInteger(event.weight) ||
    event.weight < 1
  ) {
    return 'weight must be a positive safe integer';
  }

  /*
   * ---------------------------------------------------------------
   * TIMESTAMP
   * ---------------------------------------------------------------
   */
  if (
    !Number.isSafeInteger(event.timestamp) ||
    event.timestamp <= 0
  ) {
    return 'timestamp must be a positive integer (unix ms)';
  }

  /*
   * ---------------------------------------------------------------
   * NONCE
   * ---------------------------------------------------------------
   */
  if (
    typeof event.nonce !== 'string' ||
    !HEX32.test(event.nonce)
  ) {
    return 'nonce must be 16 bytes of lowercase hex';
  }

  /*
   * ---------------------------------------------------------------
   * PIONEER UID HASH
   * ---------------------------------------------------------------
   */
  if (
    typeof event.pioneer_uid_hash !== 'string' ||
    !HEX64.test(event.pioneer_uid_hash)
  ) {
    return 'pioneer_uid_hash must be sha256 hex';
  }

  /*
   * ---------------------------------------------------------------
   * SIGNATURE
   * ---------------------------------------------------------------
   */
  if (
    typeof event.signature !== 'string' ||
    !B64_512BIT.test(event.signature)
  ) {
    return 'signature must be base64 of 64 bytes';
  }

  /*
   * ---------------------------------------------------------------
   * ELIGIBILITY OBJECT
   * ---------------------------------------------------------------
   */
  if (!isPlainObject(event.eligibility)) {
    return 'eligibility must be an object';
  }

  if (
    !exactKeys(
      event.eligibility,
      ELIGIBILITY_KEY_SET,
      ELIGIBILITY_KEYS.length
    )
  ) {
    return 'eligibility fields must be exactly kyc_passed and mainnet_migrated';
  }

  if (
    typeof event.eligibility.kyc_passed !== 'boolean' ||
    typeof event.eligibility.mainnet_migrated !== 'boolean'
  ) {
    return 'eligibility flags must be booleans';
  }

  return null;
}
