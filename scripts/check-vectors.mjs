import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { InMemoryNonceStore } from '../src/nonces.js';
import { verifySignedEvent } from '../src/verify.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const VECTORS = path.join(ROOT, 'vectors');

const registry = JSON.parse(fs.readFileSync(path.join(VECTORS, 'registry.json'), 'utf8'));
const index = JSON.parse(fs.readFileSync(path.join(VECTORS, 'index.json'), 'utf8'));
const now = index.now;

let failures = 0;
const fail = (msg) => {
  failures++;
  console.error(`FAIL ${msg}`);
};

if (registry.apps['demo-app'].keys['k-2026-active'].status !== 'active') fail('registry key status');

for (const rel of index.valid) {
  const event = JSON.parse(fs.readFileSync(path.join(VECTORS, rel), 'utf8'));
  const result = verifySignedEvent(event, { registry, nonceStore: new InMemoryNonceStore(), now });
  if (!result.ok) fail(`${rel} should be ACCEPTED (got ${result.code})`);
}

for (const entry of index.attacks) {
  const vector = JSON.parse(fs.readFileSync(path.join(VECTORS, entry.file), 'utf8'));
  const store = new InMemoryNonceStore();
  if (vector.precondition_verify_once) {
    const first = verifySignedEvent(vector.event, { registry, nonceStore: store, now });
    if (!first.ok) fail(`${entry.file} precondition verification failed (${first.code})`);
  }
  const result = verifySignedEvent(vector.event, { registry, nonceStore: store, now });
  if (result.ok || result.code !== entry.expected_code) {
    fail(`${entry.file}: expected REJECT [${entry.expected_code}], got ${result.ok ? 'ACCEPT' : result.code}`);
  }
}

const rejectedCount = index.attacks.length - failures;
if (failures > 0) {
  console.error(`RESULT: vector check failed with ${failures} failure(s)`);
  process.exit(1);
}
console.log(`vector check OK: 1 valid accepted, ${rejectedCount}/${index.attacks.length} attacks rejected`);
