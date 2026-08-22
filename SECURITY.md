# Security Policy & Threat Model

## Scope

This repository is a reference implementation of the PEP/1 engagement-event
primitive only. It does not implement token allocation, on-chain contracts, or
oracle aggregation. It is intended as auditable building material for the
engagement-reporting layer discussed in PiRC1 PR #2.

## Threat model

| Adversary | Capability | Mitigation |
|---|---|---|
| Bot farm / Sybil | submits fake engagement events | events without a valid backend signature fail at SIGNATURE; ineligible pioneers fail at ELIGIBILITY (registry-gated KYC/Mainnet) |
| Malicious user | edits weight/action/pioneer fields after capture | any mutation invalidates SIGNATURE (canonical bytes bound) |
| Replay attacker | resubmits captured valid payloads | nonce recorded per app on success; duplicates rejected with REPLAY_DETECTED |
| Stale-data attacker | delays old payloads beyond usefulness | ±5 min timestamp window |
| Compromised/misbehaving backend | signs inflated weights | WEIGHT_BOUND caps per class even for valid signatures; revocation path for compromised keys via key_id rotation |
| Cross-app forgery | uses another app's legitimately-signed payload | APP_KNOWN+KEY_ACTIVE resolve under the claimed app_id; foreign signatures fail |
| Registry tampering | modifies registry.json in transit | out of scope here: production registries MUST be content-addressed and served from launchpad-controlled infrastructure |

## Explicit limitations (v1)

### Trust boundary: authenticity is not truthfulness

PEP proves **who claimed** an event and that the claim was not altered in
transit or replayed. It does **not** prove the event happened.

```
backend signs "user X completed action A"   →  signature VALID
did action A actually happen?               →  OUT OF SCOPE (issuer trust)
```

A legitimate-but-misbehaving backend can sign false claims that fall inside its
class ceilings; this reference implementation accepts them **by design**, and a
dedicated test (`test/trust-boundary.test.js`) documents exactly that. What the
protocol guarantees even against a lying issuer:

- blast radius is capped by class ceilings (`A≤100`, `B≤10`, `C≤1`) — inflation
  beyond protocol bounds fails with `WEIGHT_OVERFLOW` even under valid
  signatures;
- claims are attributable and non-repudiable (Ed25519 under a registered,
  revocable `key_id`);
- every accepted lie is auditable evidence for slashing/delisting decisions by
  the launchpad.

Truthfulness enforcement (staking/slashing, TEE attestation, multi-party
attestation, on-chain activity proofs) is deliberately out of scope for PEP/1
and belongs to the launchpad governance layer above it.

### Other v1 limitations

- Nonce store is local state. A horizontally scaled verifier fleet MUST share it
  atomically (DB unique constraint or Redis SETNX). FileNonceStore is a demo.
- Timestamps rely on synchronized clocks (NTP); skew window is configurable.
- The eligibility registry is a plain list in this reference. Production SHOULD
  derive it from Pi's KYC/Mainnet migration records.
- No confidentiality: envelopes are public data by design. Never place raw Pi
  UIDs inside events; only sha256 hashes.

## Reporting

Open a GitHub security advisory rather than a public issue.

## Verification instructions

Every claim above is executable:

```
node --test
node src/cli.js attacks
```

CI runs both on Node 18/20/22 across Linux and Windows.
