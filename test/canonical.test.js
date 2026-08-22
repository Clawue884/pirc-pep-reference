import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalize, CanonicalError, isCanonical } from '../src/canonical.js';

test('sorts object keys lexicographically at every depth', () => {
  const input = { b: 1, a: { d: 1, c: [ { z: 1, y: 2 } ] } };
  assert.equal(canonicalize(input), '{"a":{"c":[{"y":2,"z":1}],"d":1},"b":1}');
});

test('preserves array order', () => {
  assert.equal(canonicalize([3, 1, 2]), '[3,1,2]');
});

test('serializes booleans and null as JSON', () => {
  assert.equal(canonicalize({ x: true, y: null, z: false }), '{"x":true,"y":null,"z":false}');
});

test('accepts non-negative safe integers only', () => {
  assert.equal(canonicalize(42), '42');
  assert.equal(canonicalize(0), '0');
  assert.throws(() => canonicalize(1.5), CanonicalError);
  assert.throws(() => canonicalize(-1), CanonicalError);
  assert.throws(() => canonicalize(Number.MAX_SAFE_INTEGER + 1), CanonicalError);
});

test('escapes strings deterministically', () => {
  assert.equal(canonicalize('a"b\\c'), '"a\\"b\\\\c"');
  assert.equal(canonicalize('أهلاً'), '"أهلاً"');
});

test('isCanonical accepts only canonical text', () => {
  assert.equal(isCanonical('{"a":1,"b":2}'), true);
  assert.equal(isCanonical('{"b":2,"a":1}'), false);
  assert.equal(isCanonical('{ "a": 1 }'), false);
  assert.equal(isCanonical('not json'), false);
});
