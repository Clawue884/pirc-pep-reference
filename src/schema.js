import { ACTION_CLASSES, SPEC_VERSION } from './constants.js';

const HEX64 = /^[0-9a-f]{64}$/;
const HEX32 = /^[0-9a-f]{32}$/;
const B64_512BIT = /^[A-Za-z0-9+/]{85}[AQgw]==$/;
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

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

export function schemaError(e) {
  if (!isPlainObject(e)) return 'event must be a JSON object';

  const actualKeys = Object.keys(e).sort();
  const expectedKeys = [...TOP_LEVEL_KEYS].sort();
  for (const k of actualKeys) {
    if (!TOP_LEVEL_KEYS.includes(k)) return `unknown field: ${k}`;
  }
  for (const k of expectedKeys) {
    if (!(k in e)) return `missing field: ${k}`;
  }

  if (e.v !== SPEC_VERSION) return `unsupported spec version: ${JSON.stringify(e.v)}`;
  if (typeof e.app_id !== 'string' || !APP_ID.test(e.app_id)) return 'app_id must match [a-z0-9][a-z0-9-]{2,63}';
  if (typeof e.key_id !== 'string' || !KEY_ID.test(e.key_id)) return 'key_id must match [a-zA-Z0-9][a-zA-Z0-9._-]{0,63}';
  if (!ACTION_CLASSES.includes(e.action_class)) return `action_class must be one of ${ACTION_CLASSES.join('|')}`;
  if (typeof e.action_id !== 'string' || !ACTION_ID.test(e.action_id)) return 'action_id is malformed';
  if (!Number.isSafeInteger(e.weight) || e.weight < 1) return 'weight must be a positive safe integer';
  if (!Number.isSafeInteger(e.timestamp) || e.timestamp <= 0) return 'timestamp must be a positive integer (unix ms)';
  if (typeof e.nonce !== 'string' || !HEX32.test(e.nonce)) return 'nonce must be 16 bytes of lowercase hex';
  if (typeof e.pioneer_uid_hash !== 'string' || !HEX64.test(e.pioneer_uid_hash)) return 'pioneer_uid_hash must be sha256 hex';
  if (typeof e.signature !== 'string' || !B64_512BIT.test(e.signature)) return 'signature must be base64 of 64 bytes';

  if (!isPlainObject(e.eligibility)) return 'eligibility must be an object';
  const eligKeys = Object.keys(e.eligibility).sort();
  if (eligKeys.length !== 2 || eligKeys[0] !== 'kyc_passed' || eligKeys[1] !== 'mainnet_migrated') {
    return 'eligibility fields must be exactly kyc_passed and mainnet_migrated';
  }
  if (typeof e.eligibility.kyc_passed !== 'boolean' || typeof e.eligibility.mainnet_migrated !== 'boolean') {
    return 'eligibility flags must be booleans';
  }

  return null;
}
