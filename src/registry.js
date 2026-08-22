const APP_ID_RE = /^[a-z0-9][a-z0-9-]{2,63}$/;
const KEY_ID_RE = /^[A-Za-z0-9._-]{1,128}$/;
const SHA256_HEX_RE = /^[a-f0-9]{64}$/;

function assertRegistry(registry) {
  if (
    registry === null ||
    typeof registry !== 'object' ||
    Array.isArray(registry)
  ) {
    throw new TypeError('registry must be an object');
  }

  if (
    registry.apps === null ||
    typeof registry.apps !== 'object' ||
    Array.isArray(registry.apps)
  ) {
    throw new TypeError('registry.apps must be an object');
  }

  if (
    registry.eligible_users === null ||
    typeof registry.eligible_users !== 'object' ||
    Array.isArray(registry.eligible_users)
  ) {
    throw new TypeError('registry.eligible_users must be an object');
  }
}

function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function assertAppId(appId) {
  if (typeof appId !== 'string' || !APP_ID_RE.test(appId)) {
    throw new TypeError(`invalid app_id: ${appId}`);
  }
}

function assertKeyId(keyId) {
  if (typeof keyId !== 'string' || !KEY_ID_RE.test(keyId)) {
    throw new TypeError(`invalid key_id: ${keyId}`);
  }
}

function assertPublicKey(publicKeyPem) {
  if (
    typeof publicKeyPem !== 'string' ||
    publicKeyPem.trim().length === 0
  ) {
    throw new TypeError('publicKeyPem must be a non-empty string');
  }

  /*
   * We intentionally do not parse the PEM here.
   *
   * The cryptographic verifier remains the authoritative validator
   * for the actual Ed25519 public key.
   */
}

function assertTimestamp(timestamp) {
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) {
    throw new TypeError('registeredAt must be a non-negative safe integer');
  }
}

function assertPioneerUidHash(pioneerUidHash) {
  if (
    typeof pioneerUidHash !== 'string' ||
    !SHA256_HEX_RE.test(pioneerUidHash)
  ) {
    throw new TypeError(
      'pioneerUidHash must be a lowercase SHA-256 hexadecimal string'
    );
  }
}

function appEntry(registry, appId) {
  assertRegistry(registry);
  assertAppId(appId);

  if (!hasOwn(registry.apps, appId)) {
    registry.apps[appId] = {
      keys: {}
    };
  }

  const app = registry.apps[appId];

  if (
    app === null ||
    typeof app !== 'object' ||
    Array.isArray(app)
  ) {
    throw new TypeError(`invalid registry entry for app: ${appId}`);
  }

  if (
    !app.keys ||
    typeof app.keys !== 'object' ||
    Array.isArray(app.keys)
  ) {
    throw new TypeError(`invalid key registry for app: ${appId}`);
  }

  return app;
}

export function createRegistry() {
  return {
    version: 1,
    policy_id: 'PEP1-DEFAULT-2026',
    apps: Object.create(null),
    eligible_users: Object.create(null)
  };
}

export function registerApp(registry, appId) {
  appEntry(registry, appId);
}

export function registerKey(
  registry,
  appId,
  keyId,
  publicKeyPem,
  registeredAt = Date.now()
) {
  const app = appEntry(registry, appId);

  assertKeyId(keyId);
  assertPublicKey(publicKeyPem);
  assertTimestamp(registeredAt);

  /*
   * Explicit own-property access prevents prototype pollution /
   * prototype-chain collisions.
   */
  app.keys[keyId] = {
    public_key_pem: publicKeyPem,
    status: 'active',
    registered_at: registeredAt
  };
}

export function revokeKey(registry, appId, keyId) {
  assertRegistry(registry);
  assertAppId(appId);
  assertKeyId(keyId);

  if (!hasOwn(registry.apps, appId)) {
    return false;
  }

  const app = registry.apps[appId];

  if (
    !app ||
    typeof app.keys !== 'object' ||
    !hasOwn(app.keys, keyId)
  ) {
    return false;
  }

  app.keys[keyId].status = 'revoked';

  return true;
}

export function resolveKey(registry, appId, keyId) {
  assertRegistry(registry);
  assertAppId(appId);
  assertKeyId(keyId);

  if (!hasOwn(registry.apps, appId)) {
    return null;
  }

  const app = registry.apps[appId];

  if (
    !app ||
    typeof app.keys !== 'object' ||
    Array.isArray(app.keys)
  ) {
    return null;
  }

  if (!hasOwn(app.keys, keyId)) {
    return null;
  }

  return app.keys[keyId];
}

export function markEligible(
  registry,
  pioneerUidHash,
  {
    kyc_passed = true,
    mainnet_migrated = true
  } = {}
) {
  assertRegistry(registry);
  assertPioneerUidHash(pioneerUidHash);

  if (typeof kyc_passed !== 'boolean') {
    throw new TypeError('kyc_passed must be boolean');
  }

  if (typeof mainnet_migrated !== 'boolean') {
    throw new TypeError('mainnet_migrated must be boolean');
  }

  registry.eligible_users[pioneerUidHash] = {
    kyc_passed,
    mainnet_migrated
  };
}

export function getEligibilityRecord(
  registry,
  pioneerUidHash
) {
  assertRegistry(registry);

  if (
    typeof pioneerUidHash !== 'string' ||
    !SHA256_HEX_RE.test(pioneerUidHash)
  ) {
    return null;
  }

  if (!hasOwn(registry.eligible_users, pioneerUidHash)) {
    return null;
  }

  return registry.eligible_users[pioneerUidHash];
}
