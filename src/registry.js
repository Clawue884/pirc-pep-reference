export function createRegistry() {
  return { version: 1, apps: {}, eligible_users: {} };
}

function appEntry(registry, appId) {
  if (!registry.apps[appId]) registry.apps[appId] = { keys: {} };
  return registry.apps[appId];
}

export function registerApp(registry, appId) {
  appEntry(registry, appId);
}

export function registerKey(registry, appId, keyId, publicKeyPem, registeredAt = Date.now()) {
  const app = appEntry(registry, appId);
  app.keys[keyId] = {
    public_key_pem: publicKeyPem,
    status: 'active',
    registered_at: registeredAt
  };
}

export function revokeKey(registry, appId, keyId) {
  const key = registry.apps?.[appId]?.keys?.[keyId];
  if (key) key.status = 'revoked';
}

export function resolveKey(registry, appId, keyId) {
  return registry.apps?.[appId]?.keys?.[keyId] ?? null;
}

export function markEligible(registry, pioneerUidHash, { kyc_passed = true, mainnet_migrated = true } = {}) {
  registry.eligible_users[pioneerUidHash] = { kyc_passed, mainnet_migrated };
}

export function getEligibilityRecord(registry, pioneerUidHash) {
  return registry.eligible_users?.[pioneerUidHash] ?? null;
}
