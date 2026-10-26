# Obsidian R1 research baseline

Status: experimental composition, no independent audit, no superiority claim. It is not a new primitive. The goal is an encryption system that improves on existing choices across relevant dimensions. R1 is an intentionally conservative, reproducible starting point and comparison instrument. It is not the requested breakthrough. Naming a construction does not establish originality or safety.

## Model and scope

Symmetric, single-message authenticated encryption with a uniformly random secret 32-byte key shared out of band, a freshly random public nonce, and at most 1 MiB of payload. Adversary sees full algorithm/source, chooses messages and ciphertexts, and tries to distinguish equal-length messages or produce a fresh accepted ciphertext. Key establishment and signatures are not supplied. No RSA or ML-KEM replacement claim. No replay prevention, forward secrecy, streaming, password derivation or sender identity. Length is public. The API has no caller-supplied associated-data field; only its fixed envelope header is authenticated as AAD. Key commitment and multi-key robustness are outside the current model and are not claimed. Browser compromise, malicious page updates, extensions, OS compromise, physical attacks and side-channel resistance are outside any claim. JavaScript/WASM memory erasure is best effort and not guaranteed.

## Exact R1 format and construction

Envelope: ASCII OBS1 (4 bytes), mode (1 byte), three reserved zero bytes, nonce, ciphertext, tag. Mode 0 is R1 (24-byte nonce, 32-byte tag); mode 1 is XChaCha20-Poly1305 (24-byte nonce, 16-byte tag); mode 2 is AES-256-GCM (12-byte nonce, 16-byte tag). All modes authenticate the entire header including nonce/mode/version. Reserved bytes must be zero. All trailing bytes belong to the authenticated body. Bad key sizes/modes/nonces, lengths and tags fail closed before plaintext is returned.

R1 derives 64 bytes with HKDF-SHA-256: IKM=key, salt=nonce, info=UTF-8 Obsidian/R1/stream+auth. First 32 bytes are stream key, remaining 32 are MAC key. Keystream block i = HMAC-SHA-256(stream_key, UTF-8 Obsidian/R1/block || nonce || u64be(i)), starting at zero. Ciphertext = plaintext XOR truncated keystream. Tag = HMAC-SHA-256(mac_key, header || ciphertext). Verification uses the library's tag verification before XOR decryption. This is a composition of existing ideas, not an assertion of cryptographic novelty.

## Formal obligations, not a proof

Target nonce-respecting privacy (IND-CPA) and ciphertext integrity (INT-CTXT), with a CCA security argument for their composition. A candidate argument would replace HKDF-derived keys with independent random keys, replace HMAC counter outputs with random blocks, and bound fresh tag forgeries using MAC security. This requires explicit PRF/KDF/MAC assumptions, quantitative query limits, multi-user analysis and careful composition review. That reduction has NOT been proved here. HKDF and HMAC papers prove results in their own models; citing them does not prove this exact implementation.

No unconditional or quantum-proof claim. Finite-key computational encryption cannot give information-theoretic perfect secrecy for arbitrary longer messages. For a one-time pad with independent uniform N-bit key K, C=M XOR K, Pr[C=c | M=m]=2^-N for every m,c; hence ciphertext gives no information about M under those assumptions. That does not authenticate a message, hide length or solve distribution, and reuse destroys secrecy. R1 is not a one-time pad. Shannon's bound requires key entropy at least message entropy for perfect secrecy; a reusable 256-bit key and arbitrarily long traffic cannot satisfy that bound.

## Known failures and limitations

Nonce reuse under the same key repeats the stream in all three modes: C1 XOR C2 = M1 XOR M2. Tests demonstrate recovery of a second plaintext from the first. R1 does not fix this. Browser UI never lets a caller set the nonce and requests new randomness per encryption; raw Rust API requires caller discipline. AES-GCM's shorter nonce has tighter random-collision constraints. No multi-message usage limit is claimed safe for R1. Use test data only. The raw API accepts weak/reused keys and cannot detect that error. Generated UI keys are kept only in page memory/field state; manually copied material can persist in clipboard or screenshots. No local storage or analytics are used.

Rust derived key buffers use zeroizing wrappers but dependency internal states and JS/WASM copies are not guaranteed erased. The page has no third-party scripts/fonts and no transmission operation for plaintext/keys. This is source behavior, not protection against an attacker controlling hosting. Serving over authenticated HTTPS and securing updates remain required.

## First results

The first local native benchmark shows R1 loses in throughput and ciphertext size against both supplied baselines at 4 KiB and 1 MiB. Small-message results also do not establish a broad win. Identical 32-byte master keys are used; overhead: R1 64 bytes, XChaCha 48, AES-GCM 36, including version header. This is a negative result, not a reason to suppress the baseline. See benchmark.csv, environment.txt and benchmark methodology. Benchmarks do not measure security strength. No RSA/PQ benchmarks were run; those serve different roles.

## Attack bench and review

Run cargo test --locked. All fixtures use public generated or fixed non-secret test data. The attacks suite includes complete-byte mutation, every truncation, append, bad modes/keys/nonces, chosen-ciphertext splicing, nonce-reuse recovery and deterministic parser fuzz. It does not establish cryptanalysis coverage. Independent reviewer gets complete source and may add chosen-input oracles, statistical distinguishers, cryptanalytic attacks, resource/side-channel probes and minimized regressions. Findings stay in ATTACKS.md. No real user data or outside targets.

## Research questions and next gates

1. Can a misuse-resistant established construction meet operational requirements better than R1? Compare AES-GCM-SIV/SIV with correct standards and licensing, including nonce reuse behavior, cost and metadata.
2. Build a quantitative conditional security argument before changing primitives. Seek independent cryptographic review, not only code review.
3. Add fair repeated benchmarks with medians/variance, distinct message sizes, portable and hardware-assisted paths, browser vs native, memory, code size and energy where measurable.
4. For public-key functions, establish separate KEM/signature requirements and compare standard PQ options. Do not pretend a symmetric envelope replaces them.
5. Dependency audit, structured fuzzing, reference vectors, memory-copy analysis and independent attack findings block any production recommendation.

## Sources

- Shannon, Communication Theory of Secrecy Systems (1949), section 10: https://www.cs.virginia.edu/~evans/greatworks/shannon1949.pdf
- RFC 5869, HKDF: https://www.rfc-editor.org/rfc/rfc5869
- RFC 2104, HMAC: https://www.rfc-editor.org/rfc/rfc2104
- RFC 8439, ChaCha20 and Poly1305: https://www.rfc-editor.org/rfc/rfc8439
- RustCrypto XChaCha docs and limitations: https://docs.rs/chacha20poly1305/latest/chacha20poly1305/
- HKDF API docs: https://docs.rs/hkdf/latest/hkdf/
- NIST ML-KEM role and assumptions: https://csrc.nist.gov/pubs/fips/203/final
- NIST current PQ standards overview: https://csrc.nist.gov/Projects/Post-Quantum-Cryptography
