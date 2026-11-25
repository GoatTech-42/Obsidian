# Post-quantum key establishment and signatures for Obsidian

Status: experimental, unaudited. Obsidian itself is NOT claimed to be post-quantum, secure, or better than AES-256-GCM or XChaCha20-Poly1305. This document says what the new `pq-hybrid` layer does and does not claim.

## Where the quantum risk actually is

- A symmetric cipher with a 256-bit key (Obsidian's key size) is not the weak point. The best known quantum attack on symmetric keys (Grover) roughly halves the key bits, so 256 bits stays at about 128. That holds for AES-256 and for any well-designed 256-bit cipher, and it says nothing about whether Obsidian R1 is a good cipher (it is not shown to be one, see SECURITY.md and ATTACKS.md).
- The weak points are public-key: key exchange (X25519, RSA, ECDH) and signatures (RSA, ECDSA, Ed25519). A large quantum computer running Shor's algorithm breaks all of them. No such machine exists today.
- So "making Obsidian post-quantum" means pairing it with post-quantum key establishment and signatures. A new symmetric cipher cannot do this on its own.

## What `src/hybrid.rs` adds (cargo feature `pq-hybrid`, native only, off by default)

All primitives are existing standards from the RustCrypto crates `ml-kem` 0.3.4, `ml-dsa` 0.1.2, `x25519-dalek` 3.0.0, `ed25519-dalek` 3.0.0. Nothing here is a new primitive.

- Key establishment: X25519 + ML-KEM-768 (FIPS 203). The two shared secrets, the ephemeral and recipient X25519 keys, a hash of the ML-KEM public key and the ML-KEM ciphertext go into HKDF-SHA256 to give one 32-byte key. Breaking the output needs breaking both halves. The combiner is in the style of X-Wing and the IETF hybrid drafts but it is not X-Wing and is not standardized. It needs review.
- Signatures: Ed25519 + ML-DSA-65 (FIPS 204), both over the same domain-separated message. Both must verify. ML-DSA signs in deterministic mode (allowed by FIPS 204).
- `seal_to` / `open_from`: encapsulate to a recipient key, then use the 32-byte key with an Obsidian envelope (mode 0 R1 research, mode 1 XChaCha20-Poly1305, mode 2 AES-256-GCM). The key is fresh per message. For anything real, use mode 1 or 2, not R1.
- Why hybrid and not post-quantum only: ML-KEM and ML-DSA are young and lattice-based. Public cryptanalysis of lattice schemes is active (a HAWK key-recovery attack was published in July 2026, see https://www.anthropic.com/research/discovering-cryptographic-weaknesses; HAWK is a different scheme from ML-KEM/ML-DSA). Requiring the classical half too means a break of one side does not break the whole.

## Evidence in this repo

- `tests/vectors/acvp-mlkem768-mldsa65.json`: NIST ACVP vectors (usnistgov/ACVP-Server, FIPS 203 ML-KEM-768 encapsulation 25, decapsulation 10, key generation 25; FIPS 204 ML-DSA-65 signature verification 30, with 24 expected-reject cases). All pass: `cargo test --locked --features pq-hybrid --test hybrid`. These check the third-party crates on this machine, not our combiner.
- Our wiring tests: round trip, every-nth-byte tamper rejected in all three modes, wrong recipient rejected, both KEM halves change the key, low-order X25519 point rejected, signature rejected if either half is altered.
- `cargo run --release --features pq-hybrid --example hybrid_bench`: sizes and single-run timings (see evidence/hybrid-bench.txt).

## Not covered / still required before any post-quantum claim

- No independent audit or public cryptanalysis of the combiner or this code. The underlying crates say they are unaudited.
- No constant-time or side-channel testing.
- ACVP vectors do not cover the hybrid combination; no published test vectors exist for this exact combiner.
- ML-DSA/ML-KEM implementations here are not FIPS-validated modules.
- Obsidian R1 is still a composition baseline with a known nonce-reuse failure. Nothing in this layer changes its cipher claims.
- Not wired into the WASM test bench (native only). Do not use for real secrets or keys.
