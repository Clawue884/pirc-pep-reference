import test from 'node:test';
import assert from 'node:assert/strict';

import {
  InMemoryNonceStore,
  FileNonceStore
} from '../src/nonces.js';

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

test('InMemoryNonceStore: first checkAndAdd wins', () => {
  const store = new InMemoryNonceStore();

  assert.equal(
    store.checkAndAdd('app-a:nonce-1'),
    true
  );

  assert.equal(
    store.checkAndAdd('app-a:nonce-1'),
    false
  );

  assert.equal(
    store.size(),
    1
  );
});

test('InMemoryNonceStore: different apps have independent nonce namespaces', () => {
  const store = new InMemoryNonceStore();

  assert.equal(
    store.checkAndAdd('app-a:nonce-1'),
    true
  );

  assert.equal(
    store.checkAndAdd('app-b:nonce-1'),
    true
  );

  assert.equal(
    store.size(),
    2
  );
});

test('InMemoryNonceStore: failed input does not mutate state', () => {
  const store = new InMemoryNonceStore();

  assert.throws(
    () => store.checkAndAdd(''),
    TypeError
  );

  assert.throws(
    () => store.checkAndAdd(null),
    TypeError
  );

  assert.equal(
    store.size(),
    0
  );
});

test('FileNonceStore: duplicate nonce is rejected', () => {
  const dir = fs.mkdtempSync(
    path.join(os.tmpdir(), 'pep1-nonce-')
  );

  const file = path.join(
    dir,
    'nonces.log'
  );

  try {
    const store = new FileNonceStore(file);

    assert.equal(
      store.checkAndAdd('app-a:nonce-1'),
      true
    );

    assert.equal(
      store.checkAndAdd('app-a:nonce-1'),
      false
    );

    assert.equal(
      fs.readFileSync(file, 'utf8')
        .trim()
        .split('\n').length,
      1
    );
  } finally {
    fs.rmSync(
      dir,
      {
        recursive: true,
        force: true
      }
    );
  }
});

test('FileNonceStore: state survives restart', () => {
  const dir = fs.mkdtempSync(
    path.join(os.tmpdir(), 'pep1-nonce-')
  );

  const file = path.join(
    dir,
    'nonces.log'
  );

  try {
    const first = new FileNonceStore(file);

    assert.equal(
      first.checkAndAdd('app-a:nonce-1'),
      true
    );

    const second = new FileNonceStore(file);

    assert.equal(
      second.checkAndAdd('app-a:nonce-1'),
      false
    );

    assert.equal(
      second.size(),
      1
    );
  } finally {
    fs.rmSync(
      dir,
      {
        recursive: true,
        force: true
      }
    );
  }
});

test('FileNonceStore: concurrent logical attempts have one winner', () => {
  const dir = fs.mkdtempSync(
    path.join(os.tmpdir(), 'pep1-race-')
  );

  const file = path.join(
    dir,
    'nonces.log'
  );

  try {
    const a = new FileNonceStore(file);
    const b = new FileNonceStore(file);

    const results = [
      a.checkAndAdd('app-a:race'),
      b.checkAndAdd('app-a:race')
    ];

    assert.deepEqual(
      results.sort(),
      [false, true]
    );

    const lines = fs.readFileSync(
      file,
      'utf8'
    )
      .split('\n')
      .map(x => x.trim())
      .filter(Boolean);

    assert.equal(
      lines.filter(
        x => x === 'app-a:race'
      ).length,
      1
    );
  } finally {
    fs.rmSync(
      dir,
      {
        recursive: true,
        force: true
      }
    );
  }
});
