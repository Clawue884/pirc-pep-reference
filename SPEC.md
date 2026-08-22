# PEP/1 — Programmable Engagement Proofs, v1

Normative specification for the signed engagement-event primitive referenced in
PiRC1 PR #2 ("Verifiable Engagement"). The keywords MUST, SHOULD, and MAY are to
be interpreted as described in RFC 2119.

## 1. Overview

A dApp backend attests that a specific pioneer performed a specific high-value
action by producing a canonical, Ed25519-signed JSON envelope. A verifier
(launchpad-side) validates the envelope through a fixed pipeline of checks.
Verification is deterministic: the same envelope, registry, nonce-store state,
and clock reading always yield the same verdict.

## 2. Canonical form

- Envelopes are JSON objects restricted to: objects, arrays, strings, booleans,
  `null`, and **non-negative safe integers**. Floats MUST be rejected
  (`CANONICALIZATION`).
- Canonical serialization: keys sorted lexicographically (UTF-16 code-unit
  order), no whitespace, minimal JSON string escaping. Arrays preserve order.
- This is a deliberately closed profile of RFC 8785 (JCS). By excluding floats
  we avoid ECMAScript number-formatting ambiguity entirely; every conforming
  implementation produces byte-identical output.
- The signing input MUST be: UTF-8 bytes of `"PiRC1-PEP-v1\n"` followed by the
  canonical form of the envelope with the `signature` field removed
  (domain separation + message).

## 3. Envelope

See `schema/engagement-event.schema.json` for the full field contract.

| Field | Type | Constraint |
|---|---|---|
| `v` | int | `1` |
| `app_id` | string | registered app, `^[a-z0-9][a-z0-9-]{2,63}$` |
| `key_id` | string | key version registered for the app |
| `action_class` | enum | `A` \| `B` \| `C` |
| `action_id` | string | app-defined milestone id |
| `weight` | int | `>=1`, bounded per class |
| `timestamp` | int | unix ms |
| `nonce` | string | 16 random bytes hex |
| `pioneer_uid_hash` | string | sha256 hex of UID (+ optional salt) |
| `eligibility` | object | `{ kyc_passed, mainnet_migrated }` booleans |
| `signature` | string | base64 Ed25519 (64 bytes) |

## 4. Weight ceilings

Class ceilings are protocol constants, not app choices:

| Class | Meaning | Max weight |
|---|---|---|
| A | high utility (transactions, data contribution) | 100 |
| B | medium utility (feature usage) | 10 |
| C | basic activity (navigation, login) | 1 |

The verifier MUST reject `weight > ceiling[action_class]` **even when the
signature is valid** — a misbehaving backend cannot inflate allocation beyond
protocol bounds. This implements "bounded weights / normalization" requested in
the PR #2 review.

## 5. Verification pipeline (normative order)

A verifier MUST evaluate checks in this order and stop at first failure:

1. `SCHEMA` — closed-schema validation (unknown or missing fields reject)
2. `APP_KNOWN` — `app_id` present in registry → else `UNKNOWN_APP`
3. `KEY_ACTIVE` — `key_id` resolves and status is active → else `UNKNOWN_KEY` /
   `REVOKED_KEY`
4. `CANONICALIZATION` — canonical re-serialization is stable
5. `SIGNATURE` — Ed25519 verify over §2 signing input
6. `TIMESTAMP_FRESHNESS` — `|now − timestamp| ≤ 300000ms`; future skew yields
   `TIMESTAMP_IN_FUTURE`, past yields `TIMESTAMP_EXPIRED`
7. `WEIGHT_BOUND` — §4 ceilings → else `WEIGHT_OVERFLOW`
8. `ELIGIBILITY` — self-declared flags true AND pioneer hash listed in the
   launchpad eligibility registry → else `INELIGIBLE_USER`
9. `NONCE_REPLAY` — `(app_id, nonce)` unseen; recorded only after all prior
   checks pass → else `REPLAY_DETECTED`

Recording the nonce last guarantees failed verifications never burn nonces.

## 6. Key management

- Each backend registers one or more public keys under its `app_id`, each with a
  `key_id`.
- Rotation = register new key, re-sign traffic with it, revoke old key.
  Revoked keys MUST fail at step 3 even for previously valid signatures.
- Private keys MUST live server-side only. Compromise response: register
  replacement, rotate, revoke.

## 7. Error codes

`SCHEMA`, `UNKNOWN_APP`, `UNKNOWN_KEY`, `REVOKED_KEY`, `CANONICALIZATION`,
`INVALID_SIGNATURE`, `TIMESTAMP_IN_FUTURE`, `TIMESTAMP_EXPIRED`,
`WEIGHT_OVERFLOW`, `INELIGIBLE_USER`, `REPLAY_DETECTED`.

## 8. Trust boundary

PEP/1 provides **authenticity, integrity, freshness, non-replay, and
eligibility-gating** for issuer-reported events. It does NOT provide
**truthfulness**: a conforming backend can sign a false claim that passes all
nine checks if it stays within class ceilings. Implementations and reviewers
MUST NOT represent PEP as proof that reported activity occurred. The blast
radius of issuer misbehavior MUST be assumed bounded by §4 ceilings plus
launchpad-side governance (revocation, delisting, slashing), not by this
primitive.

## 9. Conformance

An implementation conforms if it:

1. accepts every vector in `vectors/index.json` marked valid;
2. rejects every attack vector with exactly its `expected_code`;
3. produces byte-identical canonical output for any conforming envelope.

`npm run gen:vectors` regenerates vectors and re-checks conformance.
