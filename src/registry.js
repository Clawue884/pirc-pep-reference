// Prototype-safe property access: registry objects may be loaded from
// JSON.parse output or hand-built by embedders, so every lookup uses own-
// property semantics. Inherited names like "constructor" or "toString" can
// never masquerade as registered apps, keys, or users.
function ownGet(obj, key) {
  if (obj === null || typeof obj !== 'object') return undefined;
  return Object.hasOwn(obj, key) ? obj[key] : undefined;
}

function ownSet(obj, key, value) {
  if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
    throw new TypeError(`refusing to write protected key: ${key}`);
  }
  obj[key] = value;
}

export function createRegistry() {
  return { version: 1, apps: {}, eligible_users: {} };
}

function appEntry(registry, appId) {
  let app = ownGet(registry.apps, appId);
  if (!app) {
    app = { keys: {} };
    ownSet(registry.apps, appId, app);
  }
  return app;
}

export function registerApp(registry, appId) {
  appEntry(registry, appId);
}

export function registerKey(registry, appId, keyId, publicKeyPem, registeredAt = Date.now()) {
  const app = appEntry(registry, appId);
  ownSet(app.keys, keyId, {
    public_key_pem: publicKeyPem,
    status: 'active',
    registered_at: registeredAt
  });
}

export function revokeKey(registry, appId, keyId) {
  const app = ownGet(registry?.apps, appId);
  const key = app ? ownGet(app.keys, keyId) : undefined;
  if (key) key.status = 'revoked';
}

export function hasApp(registry, appId) {
  return ownGet(registry?.apps, appId) !== undefined;
}

export function resolveKey(registry, appId, keyId) {
  const app = ownGet(registry?.apps, appId);
  if (!app) return null;
  return ownGet(app.keys, keyId) ?? null;
}

export function markEligible(registry, pioneerUidHash, { kyc_passed = true, mainnet_migrated = true } = {}) {
  if (typeof pioneerUidHash !== 'string' || !/^(h1:[A-Za-z0-9_-]{43}|[0-9a-f]{64})$/.test(pioneerUidHash)) {
    throw new TypeError('markEligible: pioneerUidHash must be an h1 HMAC tag or sha256 hex');
  }
  ownSet(registry.eligible_users, pioneerUidHash, { kyc_passed, mainnet_migrated });
}

export function getEligibilityRecord(registry, pioneerUidHash) {
  return ownGet(registry?.eligible_users, pioneerUidHash) ?? null;
}
