#!/usr/bin/env python3
"""Cross-implementation verifier for PEP/1 vectors.

Independent re-verification of the committed test vectors using only the
Python standard library: canonical JSON, Ed25519 (RFC 8032), and the same
9-step pipeline order as src/verify.js.

No third-party packages. Run: python scripts/cross-verify.py
"""
import base64
import hashlib
import json
import os
import sys
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
VECTORS = os.path.join(ROOT, "vectors")
DOMAIN = b"PiRC1-PEP-v1\n"

# ---------------------------------------------------------------- Ed25519 ---
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, P - 2, P)


_D = (-121665 * _inv(121666)) % P
_I = pow(2, (P - 1) // 4, P)


def _xrecover(y):
    xx = ((y * y - 1) * _inv(_D * y * y + 1)) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * _I) % P
        if (x * x - xx) % P != 0:
            raise ValueError("point not on curve")
    if x % 2 != 0:
        x = P - x
    return x


_BY = (4 * _inv(5)) % P
_B = [_xrecover(_BY), _BY % P]
_IDENT = [0, 1]


def _edwards_add(pt_q, pt_p):
    x1, y1 = pt_q
    x2, y2 = pt_p
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _D * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _D * x1 * x2 * y1 * y2)
    return [x3 % P, y3 % P]


def _scalarmult(pt, e):
    q = _IDENT
    while e > 0:
        if e & 1:
            q = _edwards_add(q, pt)
        pt = _edwards_add(pt, pt)
        e >>= 1
    return q


def _decode_point(s):
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    sign = s[31] >> 7
    x = _xrecover(y)
    if x == 0 and sign != 0:
        raise ValueError("non-canonical point")
    if x & 1 != sign:
        x = P - x
    return [x, y]


def ed25519_verify(public_key_32: bytes, message: bytes, signature_64: bytes) -> bool:
    r_bytes = signature_64[:32]
    s_bytes = signature_64[32:]
    s = int.from_bytes(s_bytes, "little")
    if s >= L:
        return False
    try:
        a = _decode_point(public_key_32)
        r = _decode_point(r_bytes)
    except (ValueError, IndexError):
        return False
    k = int.from_bytes(hashlib.sha512(r_bytes + public_key_32 + message).digest(), "little") % L
    left = _scalarmult(_B, s)
    right = _edwards_add(r, _scalarmult(a, k))
    return left == right


# ------------------------------------------------------- canonicalization ---
MAX_DEPTH = 64


def canonicalize(value, depth=0) -> str:
    if depth > MAX_DEPTH:
        raise ValueError(f"canonicalization depth exceeded {MAX_DEPTH}")
    if value is None or isinstance(value, bool):
        return json.dumps(value)
    if isinstance(value, int):
        if value < 0:
            raise ValueError("negative integer outside PEP profile")
        return str(value)
    if isinstance(value, float):
        raise ValueError("floats are outside the PEP profile")
    if isinstance(value, str):
        return json.dumps(unicodedata.normalize("NFC", value), ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(canonicalize(v, depth + 1) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(unicodedata.normalize("NFC", k) for k in value.keys())
        return (
            "{"
            + ",".join(
                json.dumps(k, ensure_ascii=False) + ":" + canonicalize(value[k], depth + 1)
                for k in keys
            )
            + "}"
        )
    raise ValueError(f"unsupported type: {type(value).__name__}")


SPKI_ED25519_PREFIX = bytes.fromhex("302a300506032b6570032100")


def pem_to_raw32(pem: str) -> bytes:
    body = "".join(
        line for line in pem.strip().splitlines() if "-----" not in line
    )
    der = base64.b64decode(body)
    if not der.startswith(SPKI_ED25519_PREFIX) or len(der) != 44:
        raise ValueError("not an Ed25519 SPKI PEM")
    return der[12:]


TIMESTAMP_WINDOW_MS = 300_000
WEIGHT_CEILINGS = {"A": 100, "B": 10, "C": 1}


class NonceStore:
    def __init__(self):
        self.seen = set()

    def has(self, key):
        return key in self.seen

    def add(self, key):
        self.seen.add(key)


def verify_event(event, registry, nonce_store, now):
    checks = []

    def reject(check, code):
        checks.append((check, False))
        return False, code, checks

    required = {
        "v", "app_id", "key_id", "action_class", "action_id", "weight",
        "timestamp", "nonce", "pioneer_uid_hash", "eligibility", "signature",
    }
    if not isinstance(event, dict) or set(event.keys()) != required:
        return reject("SCHEMA", "SCHEMA")
    if event["v"] != 1:
        return reject("SCHEMA", "SCHEMA")
    checks.append(("SCHEMA", True))

    apps = registry.get("apps") or {}
    if event["app_id"] not in apps:
        return reject("APP_KNOWN", "UNKNOWN_APP")
    checks.append(("APP_KNOWN", True))

    key_rec = apps[event["app_id"]].get("keys", {}).get(event["key_id"])
    if key_rec is None:
        return reject("KEY_ACTIVE", "UNKNOWN_KEY")
    if key_rec.get("status") != "active":
        return reject("KEY_ACTIVE", "REVOKED_KEY")
    checks.append(("KEY_ACTIVE", True))

    body = {k: v for k, v in event.items() if k != "signature"}
    try:
        c1 = canonicalize(body)
        c2 = canonicalize(json.loads(c1))
    except ValueError:
        return reject("CANONICALIZATION", "CANONICALIZATION")
    if c1 != c2:
        return reject("CANONICALIZATION", "CANONICALIZATION")
    checks.append(("CANONICALIZATION", True))

    try:
        sig = base64.b64decode(event["signature"], validate=True)
        pub = pem_to_raw32(key_rec["public_key_pem"])
    except Exception:
        return reject("SIGNATURE", "INVALID_SIGNATURE")
    if len(sig) != 64 or not ed25519_verify(pub, DOMAIN + c1.encode("utf-8"), sig):
        return reject("SIGNATURE", "INVALID_SIGNATURE")
    checks.append(("SIGNATURE", True))

    delta = now - event["timestamp"]
    if delta < -TIMESTAMP_WINDOW_MS:
        return reject("TIMESTAMP_FRESHNESS", "TIMESTAMP_IN_FUTURE")
    if delta > TIMESTAMP_WINDOW_MS:
        return reject("TIMESTAMP_FRESHNESS", "TIMESTAMP_EXPIRED")
    checks.append(("TIMESTAMP_FRESHNESS", True))

    if event["weight"] > WEIGHT_CEILINGS[event["action_class"]]:
        return reject("WEIGHT_BOUND", "WEIGHT_OVERFLOW")
    checks.append(("WEIGHT_BOUND", True))

    elig = event.get("eligibility") or {}
    elig_rec = (registry.get("eligible_users") or {}).get(event["pioneer_uid_hash"])
    ok_self = elig.get("kyc_passed") is True and elig.get("mainnet_migrated") is True
    ok_registry = (
        elig_rec is not None
        and elig_rec.get("kyc_passed") is True
        and elig_rec.get("mainnet_migrated") is True
    )
    if not (ok_self and ok_registry):
        return reject("ELIGIBILITY", "INELIGIBLE_USER")
    checks.append(("ELIGIBILITY", True))

    nonce_key = f"{event['app_id']}:{event['nonce']}"
    if nonce_store.has(nonce_key):
        return reject("NONCE_REPLAY", "REPLAY_DETECTED")
    nonce_store.add(nonce_key)
    checks.append(("NONCE_REPLAY", True))

    return True, None, checks


def main():
    with open(os.path.join(VECTORS, "registry.json"), encoding="utf-8") as f:
        registry = json.load(f)
    with open(os.path.join(VECTORS, "index.json"), encoding="utf-8") as f:
        index = json.load(f)

    now = index["now"]
    failures = 0

    for rel in index["valid"]:
        with open(os.path.join(VECTORS, rel), encoding="utf-8") as f:
            event = json.load(f)
        ok, code, _ = verify_event(event, registry, NonceStore(), now)
        if not ok:
            failures += 1
            print(f"FAIL {rel}: expected ACCEPT, got {code}")

    rejected = 0
    for entry in index["attacks"]:
        with open(os.path.join(VECTORS, entry["file"]), encoding="utf-8") as f:
            vector = json.load(f)
        store = NonceStore()
        if vector.get("precondition_verify_once"):
            ok_pre, _, _ = verify_event(vector["event"], registry, store, now)
            if not ok_pre:
                failures += 1
                print(f"FAIL {entry['file']}: precondition verification failed")
                continue
        ok, code, _ = verify_event(vector["event"], registry, store, now)
        if ok or code != entry["expected_code"]:
            failures += 1
            got = "ACCEPT" if ok else code
            print(f"FAIL {entry['file']}: expected REJECT [{entry['expected_code']}], got {got}")
        else:
            rejected += 1

    total = len(index["attacks"])
    if failures:
        print(f"RESULT: cross-verification FAILED ({failures} failure(s))")
        sys.exit(1)
    print(f"CROSS-VERIFICATION OK (pure Python): 1 valid accepted, {rejected}/{total} attacks rejected")


if __name__ == "__main__":
    main()
