# TRACEABILITY — Proof of Correspondence

Every requirement from the PiRC1 PR #2 review thread maps to an implementation
unit, a test, and (where applicable) a dedicated adversarial scenario. If you
change any of these, the mapping breaks on purpose — update it in the same PR.

| Req ID | Requirement (source) | Implementation | Tests | Attacks / Vectors | Result |
|---|---|---|---|---|---|
| PEP-REQ-001 | Canonical serialization rules frozen (review, Feb 24) | `src/canonical.js` | `test/canonical.test.js` | 13_unknown_field_injection, 12_missing_field (`vectors/attacks/`) | deterministic bytes; malformed input → `SCHEMA` |
| PEP-REQ-002 | Closed schema / normative validation | `src/schema.js`, `schema/engagement-event.schema.json` | happy path + every negative branch via suite | all `SCHEMA` vectors | reject with stable code |
| PEP-REQ-003 | Standardized signature scheme (Ed25519) (review: "Is signature scheme standardized?") | `src/keys.js`, signing input = `PiRC1-PEP-v1\n` + canonical body (SPEC §2) | `test/verify.test.js` (SIGNATURE check) | 03_invalid_signature, 11_cross_app_forgery | forged/foreign sig → `INVALID_SIGNATURE` |
| PEP-REQ-004 | App-specific API key registration | `src/registry.js` `registerApp/registerKey`; CLI `init-reg/add-key` | `test/cli.test.js` end-to-end | 09_unknown_app → `UNKNOWN_APP`; 16_unknown_key_claim → `UNKNOWN_KEY` | unregistered app/key rejected |
| PEP-REQ-005 | Key rotation & revocation governance | `revokeKey`, `key.status`, pipeline step 3 | revoked-key path covered per-run | 10_revoked_key → `REVOKED_KEY` | previously-valid key stops validating |
| PEP-REQ-006 | Replay protection, globally namespaced (review: "globally scoped or namespaced") | nonce keyed `(app_id, nonce)`; recorded only after full pass — `src/nonces.js`, `src/verify.js` | `test/verify.test.js` "does not burn the nonce" | 01_replay_attack, 02_nonce_reuse → `REPLAY_DETECTED` | duplicates rejected; failures don't consume nonces |
| PEP-REQ-007 | Bounded weights / no utility inflation (review: "Weight bounding", "normalization ceiling") | class ceilings `A=100,B=10,C=1` enforced post-signature — SPEC §4 | `test/trust-boundary.test.js` #2 | 08_weight_inflation → `WEIGHT_OVERFLOW` | valid-signed inflation rejected |
| PEP-REQ-008 | KYC/Mainnet eligibility binding (kokkalis: "KYC-verified and migrated to Mainnet") | signed `eligibility` block **and** launchpad-side registry cross-check — `src/registry.js`, verify step 8 | `test/verify.test.js` kyc/mainnet mismatch tests | 15_ineligible_user, 17_registry_kyc_false, 18_registry_mainnet_false, 19_unregistered_pioneer → `INELIGIBLE_USER` | self-declared flags alone are insufficient |
| PEP-REQ-009 | Deterministic validation (review: "deterministically verifiable") | fixed 9-step order, injectable clock — `src/verify.js` | determinism test in `test/verify.test.js` | whole suite rerun in CI on Node 18/20/22 × Linux/Windows | same inputs ⇒ same verdict |
| PEP-REQ-010 | Timestamp freshness window | ±5 min window, future-skew split — SPEC §5.6 | covered by suite | 06_timestamp_expired, 07_timestamp_future | stale/future payloads rejected |
| PEP-REQ-011 | Adversarial threat matrix (review: "adversarial threat matrix") | `SECURITY.md` threat table + executable matrix | `test/attacks.test.js` asserts every scenario | 19 scenarios, `npm run attacks` | **19/19 rejected**, exit code gates CI |
| PEP-REQ-012 | Cross-implementation reproducibility | committed vectors regenerated+rechecked each run; independent Python verifier `scripts/cross-verify.py` (RFC 8032, stdlib only) | `scripts/check-vectors.mjs`, CI python job | all vectors re-verified cross-language | byte-identical canonical form across runtimes |
| PEP-REQ-013 | Trust boundary honesty (issuer collusion question, review: "What prevents backend collusion inflation?") | SPEC §8, SECURITY.md "Trust boundary" | `test/trust-boundary.test.js` #1 documents accepted-by-design lying issuer within ceilings | n/a (out-of-scope attack class, explicitly documented) | authenticity ≠ truthfulness, stated and tested |

## Regeneration

```
npm run gen:vectors   # regenerates vectors/ AND re-checks conformance
node scripts/cross-verify.py   # independent Python verification of the same vectors
```
