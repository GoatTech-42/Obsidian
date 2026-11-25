#!/usr/bin/env python3
"""Independent cross-check of src/hybrid.rs using Python `cryptography` (OpenSSL-backed ML-KEM,
ML-DSA, X25519, Ed25519) and hashlib (SHAKE256, SHA3-256). The X-Wing steps are re-implemented
here from draft-connolly-cfrg-xwing-kem-11 section 5, sharing no code with the Rust crate.
Run from the repo root: python3 scripts/xcheck_hybrid.py"""
import hashlib, json, os, subprocess, sys
from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa, x25519, ed25519
from cryptography.hazmat.primitives import serialization as ser

LABEL = bytes.fromhex("5c2e2f2f5e5c")
RAW = dict(encoding=ser.Encoding.Raw, format=ser.PublicFormat.Raw)

def rust(*a):
    return subprocess.run(["cargo", "run", "-q", "--release", "--locked", "--features", "pq-hybrid", "--example", "hybrid_xcheck", "--", *a], check=True, capture_output=True, text=True).stdout.strip()

def expand(sk):
    e = hashlib.shake_256(sk).digest(96)
    kem = mlkem.MLKEM768PrivateKey.from_seed_bytes(e[:64])
    xs = x25519.X25519PrivateKey.from_private_bytes(e[64:96])
    return kem, xs, xs.public_key().public_bytes(**RAW)

def combiner(ss_m, ss_x, ct_x, pk_x):
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + LABEL).digest()

for run in range(5):
    d = json.loads(rust("emit"))
    sk, pk, ct, ss = (bytes.fromhex(d[k]) for k in ("sk", "pk", "ct", "ss"))
    kem, xs, pk_x = expand(sk)
    # 1. same public key from the same seed
    assert kem.public_key().public_bytes_raw() + pk_x == pk, "public key differs"
    # 2. Python decapsulates Rust's ciphertext to the same secret
    ct_m, ct_x = ct[:1088], ct[1088:]
    ss_py = combiner(kem.decapsulate(ct_m), xs.exchange(x25519.X25519PublicKey.from_public_bytes(ct_x)), ct_x, pk_x)
    assert ss_py == ss, "python decapsulation differs"
    # 3. Python encapsulates to Rust's public key, Rust decapsulates to the same secret
    ek_m = mlkem.MLKEM768PublicKey.from_public_bytes(pk[:1184])
    ss_m, ct_m2 = ek_m.encapsulate()
    esk = x25519.X25519PrivateKey.generate()
    ct_x2 = esk.public_key().public_bytes(**RAW)
    ss2 = combiner(ss_m, esk.exchange(x25519.X25519PublicKey.from_public_bytes(pk[1184:])), ct_x2, pk[1184:])
    assert bytes.fromhex(rust("decap", sk.hex(), (ct_m2 + ct_x2).hex())) == ss2, "rust decapsulation differs"
    # 4. both signature halves verify under independent implementations
    vk, msg, sig = (bytes.fromhex(d[k]) for k in ("vk", "msg", "sig"))
    ed25519.Ed25519PublicKey.from_public_bytes(vk[:32]).verify(sig[:64], b"Obsidian/hybrid-sig/v1\x00" + msg)
    mldsa.MLDSA65PublicKey.from_public_bytes(vk[32:]).verify(sig[64:], msg, b"Obsidian/hybrid-sig/v1")
print("cross-check ok: 5 runs, X-Wing KEM both directions, Ed25519 and ML-DSA-65 signatures verified by cryptography", __import__("cryptography").__version__)
