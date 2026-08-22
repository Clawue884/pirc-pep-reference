import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { verifySignedEvent } from '../src/verify.js';
import { InMemoryNonceStore } from '../src/nonces.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');

const VECTORS_DIR = path.join(ROOT, 'vectors');

function readJson(file) {
  return JSON.parse(
    fs.readFileSync(file, 'utf8')
  );
}

function findFiles(dir) {
  if (!fs.existsSync(dir)) {
    return [];
  }

  const result = [];

  for (const entry of fs.readdirSync(dir, {
    withFileTypes: true
  })) {
    const full = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      result.push(...findFiles(full));
    } else if (entry.isFile() && entry.name.endsWith('.json')) {
      result.push(full);
    }
  }

  return result.sort();
}

function normalizeVector(vector) {
  /*
   * Accept both the current vector style and a minimal conformance
   * style without making the protocol itself dependent on the test
   * representation.
   */
  const event =
    vector.event ??
    vector.signed_event ??
    vector.envelope ??
    vector.input;

  const registry =
    vector.registry ??
    vector.state;

  const expected =
    vector.expected ??
    vector.expected_result ??
    vector.result;

  if (!event) {
    throw new Error('vector is missing event/envelope/input');
  }

  if (!registry) {
    throw new Error('vector is missing registry/state');
  }

  return {
    event,
    registry,
    expected
  };
}

function createNonceStore() {
  return new InMemoryNonceStore();
}

function verifyVector(vector) {
  const {
    event,
    registry,
    expected
  } = normalizeVector(vector);

  const nonceStore = createNonceStore();

  const result = verifySignedEvent(event, {
    registry,
    nonceStore,
    now: vector.now ?? Date.now()
  });

  return {
    result,
    expected
  };
}

test('PEP/1 conformance: every committed JSON vector is deterministic', () => {
  const files = findFiles(VECTORS_DIR);

  assert.ok(
    files.length > 0,
    'no JSON conformance vectors found'
  );

  for (const file of files) {
    /*
     * registry.json is state, not itself a test vector.
     */
    if (path.basename(file) === 'registry.json') {
      continue;
    }

    const vector = readJson(file);

    /*
     * Attack vectors may use a different representation.
     * Skip files that are clearly metadata-only.
     */
    if (
      !vector.event &&
      !vector.signed_event &&
      !vector.envelope &&
      !vector.input
    ) {
      continue;
    }

    const first = verifyVector(vector);
    const second = verifyVector(vector);

    assert.deepEqual(
      first.result,
      second.result,
      `non-deterministic result: ${path.relative(ROOT, file)}`
    );

    if (
      first.expected &&
      typeof first.expected.code === 'string'
    ) {
      assert.equal(
        first.result.code,
        first.expected.code,
        `unexpected code: ${path.relative(ROOT, file)}`
      );
    }

    if (
      first.expected &&
      typeof first.expected.ok === 'boolean'
    ) {
      assert.equal(
        first.result.ok,
        first.expected.ok,
        `unexpected verdict: ${path.relative(ROOT, file)}`
      );
    }
  }
});

test('PEP/1 conformance: repeated verification produces replay rejection', () => {
  const files = findFiles(
    path.join(VECTORS_DIR, 'valid')
  );

  assert.ok(
    files.length > 0,
    'no valid vector found'
  );

  const vector = readJson(files[0]);
  const {
    event,
    registry
  } = normalizeVector(vector);

  const nonceStore = createNonceStore();

  const options = {
    registry,
    nonceStore,
    now: vector.now ?? Date.now()
  };

  const first = verifySignedEvent(
    event,
    options
  );

  assert.equal(
    first.ok,
    true,
    'first verification must pass'
  );

  const second = verifySignedEvent(
    event,
    options
  );

  assert.equal(
    second.ok,
    false
  );

  assert.equal(
    second.code,
    'REPLAY_DETECTED'
  );

  assert.equal(
    nonceStore.size(),
    1
  );
});

test('PEP/1 conformance: failed verification does not burn nonce', () => {
  const files = findFiles(
    path.join(VECTORS_DIR, 'valid')
  );

  assert.ok(files.length > 0);

  const vector = readJson(files[0]);

  const {
    event,
    registry
  } = normalizeVector(vector);

  const nonceStore = createNonceStore();

  const badEvent = {
    ...event,
    signature: event.signature.slice(0, -2) + 'AA'
  };

  const failed = verifySignedEvent(
    badEvent,
    {
      registry,
      nonceStore,
      now: vector.now ?? Date.now()
    }
  );

  assert.equal(
    failed.ok,
    false
  );

  assert.equal(
    failed.code,
    'INVALID_SIGNATURE'
  );

  assert.equal(
    nonceStore.size(),
    0,
    'failed verification must not consume nonce'
  );
});
