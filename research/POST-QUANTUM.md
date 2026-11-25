# Post-quantum key establishment and signatures for Obsidian

Status: experimental, unaudited. Obsidian itself is NOT claimed to be post-quantum, secure, or better than AES-256-GCM or XChaCha20-Poly1305. This file says what the optional `pq-hybrid` layer does, what evidence exists, and which gates remain before any post-quantum claim could be made.

## Claimed and not claimed (read this first)

Claimed, with the evidence behind each:
- `src/hybrid.rs` implements X-Wing (draft-connolly-cfrg-xwing-kem-11) and matches the draft's 3 official test vectors, and an independent Python re-implementation (OpenSSL-backed ML-KEM and X25519) agrees in both directions over 5 random runs.
- The ML-KEM-768 and ML-DSA-65 crates reproduce NIST ACVP vectors on our machine (ML-KEM-768: 25 encapsulation, 10 decapsulation, 25 key generation; ML-DSA-65: 30 verification, of which 24 are expected rejects).
- A hybrid signature is accepted only if both the Ed25519 half and the ML-DSA-65 half verify (tested by corrupting each half alone).
- Parsers did not crash in about 8 minutes of libFuzzer and 2000 random mutations (a smoke test, not a campaign).

Not claimed:
- That Obsidian, its cipher, or R1 is post-quantum, secure, uncrackable, novel, or better than AES-256-GCM or XChaCha20-Poly1305. It is not shown to be any of these.
- That this layer is audited, constant-time, side-channel resistant, FIPS-validated, or formally verified.
- That the Ed25519 + ML-DSA-65 combination has a proof or a standard behind it.
- That X-Wing is a published standard. It is an Independent Submission Internet-Draft with a paper-proof of its own, and that proof covers the construction, not this code.
- That the raw `seal` API resists nonce reuse. It does not. The hybrid API avoids reuse by using a fresh key per message.

Known limits: native only (not in the WASM bench), test keys only, no real secrets, and the open gates listed at the end of this file.

## Where the quantum risk actually is

- A symmetric cipher with a 256-bit key is not the weak point. The best known quantum attack on symmetric keys (Grover) roughly halves the key bits, so 256 bits stays at about 128. That is true for AES-256 and for any well-designed 256-bit cipher. It says nothing about whether Obsidian R1 is a good cipher (it is not shown to be one, see SECURITY.md and ATTACKS.md).
- The weak points are public-key: key exchange (X25519, ECDH, RSA) and signatures (RSA, ECDSA, Ed25519). A large quantum computer running Shor's algorithm breaks all of them. No such machine exists today; resource estimates keep falling.
- So "pairing Obsidian with post-quantum" means pairing it with post-quantum key establishment and signatures. A new symmetric cipher cannot do this on its own.

## What `src/hybrid.rs` is (cargo feature `pq-hybrid`, native only, off by default)

Only existing standards from RustCrypto crates: `ml-kem` 0.3.4, `ml-dsa` 0.1.2, `x25519-dalek` 3.0.0, `ed25519-dalek` 3.0.0, `sha3` 0.12.0, `shake` 0.1.0. No new primitive and no new combiner.

### KEM: X-Wing, unchanged

X25519 + ML-KEM-768 exactly as in draft-connolly-cfrg-xwing-kem-11 (https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/): 32-byte decapsulation key expanded with SHAKE256 to ML-KEM seed (64 bytes) and X25519 secret (32 bytes); shared secret = SHA3-256(ss_M || ss_X || ct_X || pk_X || 5c2e2f2f5e5c). Public key 1216 bytes, ciphertext 1120 bytes.

- Security argument: the X-Wing paper (Barbosa, Connolly, Duarte, Kaiser, Schwabe, Varner, Westerbaan, https://eprint.iacr.org/2024/039) proves X-Wing is classically IND-CCA secure if the strong Diffie-Hellman assumption holds in the X25519 group (random oracle model), and post-quantum IND-CCA secure if ML-KEM-768 is IND-CCA secure and SHA3-256 is a secure PRF (standard model). In short: secure if either X25519 or ML-KEM-768 is secure. The authors stress this relies on the concrete choices and may not carry to other pairings.
- We do not claim this proof is ours, and we do not modify the construction. An earlier version of this branch used our own HKDF-based combiner. It had no proof, so it was replaced.
- The draft is an Independent Submission Internet-Draft. It is not an RFC and not a NIST standard.
- One local addition: decapsulation/encapsulation reject an all-zero X25519 output (low-order point). The draft does not require it. It does not change outputs for honest inputs.
- A tampered ML-KEM ciphertext yields a different key rather than an error (ML-KEM implicit rejection), as in the draft. `open_from` then fails on the Obsidian envelope authentication.

### Signatures: Ed25519 AND ML-DSA-65 (our wiring, no standard)

Both signatures are over the same domain-separated message; the combined signature is 3373 bytes and both halves must verify. ML-DSA signs in deterministic mode (permitted by FIPS 204). Informal argument only: producing a signature that verifies requires a valid forgery under BOTH independent keys, so the pair is unforgeable if either scheme is. We have not written this as a proof, we did not check it against the hybrid-signature literature, and it says nothing about stronger properties (strong unforgeability, key-substitution or binding properties). Treat it as a design choice that needs review.

### Sealing

`seal_to` / `open_from`: X-Wing encapsulate, then the 32-byte key seals with an Obsidian envelope (mode 0 R1 research, 1 XChaCha20-Poly1305, 2 AES-256-GCM). The key is fresh per message. For anything real use mode 1 or 2, not R1.

### Why hybrid and not post-quantum only

ML-KEM and ML-DSA are young lattice schemes under active cryptanalysis (for example Anthropic reported a key-recovery attack on HAWK, a different lattice signature candidate, https://www.anthropic.com/research/discovering-cryptographic-weaknesses). Requiring the classical half as well means a break of one side does not break the whole. Rumors in November 2026 about AI-found weaknesses in RSA or lattice schemes were unverified when this was written.

## Evidence in this repo

| Check | What it covers | Result |
| --- | --- | --- |
| `tests/vectors/xwing-draft11.json` (official draft vectors, 3) | our X-Wing: key from seed, derandomized encapsulation, decapsulation | match |
| `tests/vectors/acvp-mlkem768-mldsa65.json` (NIST ACVP, usnistgov/ACVP-Server) | ML-KEM-768 encapsulation 25, decapsulation 10, keygen 25; ML-DSA-65 verify 30 (24 expected rejects) | match |
| `scripts/xcheck_hybrid.py` | independent re-implementation of X-Wing in Python on top of OpenSSL-backed ML-KEM, X25519 via `cryptography` 50.0.2; Ed25519 and ML-DSA-65 verification by `cryptography`; both directions (Rust to Python, Python to Rust), 5 runs | match |
| `tests/hybrid.rs` wiring tests | round trip, tamper in all modes, wrong recipient, both KEM halves bind the key, low-order point rejected, either signature half alone cannot pass, 2000 random mutations all rejected, malformed lengths never panic | pass |

Run: `cargo test --locked --features xwing-derand --test hybrid` and `python3 scripts/xcheck_hybrid.py`.
Benchmarks: `cargo run --release --features pq-hybrid --example hybrid_bench` (evidence/hybrid-bench.txt, single machine, single run).

## Gates still open before any post-quantum claim

1. No independent audit or public cryptanalysis of this layer. The dependencies say they are unaudited.
2. No constant-time or side-channel testing (timing, cache, power). Not measured at all.
3. The signature AND wiring has no written proof and no standard behind it.
4. X-Wing is a draft, not an RFC. Its proof covers X-Wing, not this code; correctness here rests on test vectors and the Python cross-check.
5. Implementations are not FIPS-validated modules.
6. Obsidian R1, the cipher, still has a known nonce-reuse failure, loses to AES-256-GCM and XChaCha20-Poly1305 on speed and size, and has no public cryptanalysis. Post-quantum status of the cipher cannot be claimed from this layer.
7. Not wired into the WASM test bench (native only). Do not use for real keys or secrets.
8. Fuzzing so far is short: about 60 s of libFuzzer on the new hybrid target plus 36 s each on the two older targets, no crashes (evidence/fuzz-2026-11-25.md). A real campaign runs for days with a seed corpus.
9. Nonce reuse in raw `seal` is not fixed. Through the hybrid API every message gets a fresh key, so reuse cannot occur there (tested). A nonce-misuse-resistant mode would be a new unreviewed design; use AES-GCM-SIV (existing standard, RFC 8452) if misuse resistance is needed.

Any wording stronger than "experimental hybrid layer built from NIST ML-KEM/ML-DSA and the X-Wing draft, unaudited" is not supported by this evidence.
