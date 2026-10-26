# Attack record

Builder-executed tests only so far. Independent attack review pending.

- Demonstrated key+nonce reuse plaintext recovery in R1, XChaCha20-Poly1305 and AES-GCM. This is an expected but serious misuse failure, not repaired by the candidate. Repro: cargo test --locked reuse_exposes_plaintext_xor -- --nocapture.
- Mutation/splice/parser probes currently reject their invalid inputs. This does not establish security or exhaustive coverage.
- Strong security claims, production recommendation, novelty and superiority all remain unsupported.

Every independent finding must include source pin, command, inputs, observed vs expected behavior, impact, fix or accepted limitation, and regression retest. Do not mark no findings as no vulnerabilities.

## Independent round 1

No new candidate flaw reported in tested scope. Known nonce-reuse plaintext recovery confirmed. Independent harness retained under research/independent with portability/counting/input corrections documented in REPRO.md. Fresh adapted replay rejects 377 tamper/truncation/append probes and 6000 fuzz cases without panic; both independent fixtures match. This is not proof, certification, exhaustive coverage or a completed CCA reduction. No real user data or outside targets were involved.
