# Post-v1 research backlog

Owner: one dedicated ongoing worker, with independent review on substantive changes. No self-approval for security claims.

1. Reconcile independent attacker findings with source-pinned fixes and failing-then-passing regression evidence.
2. Formally specify nonce-respecting privacy/integrity games and a quantitative conditional argument; identify proof gaps rather than asserting assumed primitive safety as proof.
3. Compare established misuse-resistant AES-GCM-SIV/SIV to R1/AES-GCM/XChaCha, including explicit nonce-reuse attack outcomes. Prefer a negative result over an invented win.
4. Repeat benchmarks over multiple runs, report median and spread, portable/hardware-assisted/native/browser paths, memory/code-size/resource cost. Never compare different cryptographic jobs in one speed ranking.
5. Structure fuzzing with minimized failures, independent vectors for each baseline, dependency advisories and key-copy/zeroization review. Budget local jobs and stop on resource saturation.
6. Build separate KEM/signature research only after exact functional requirements are stated, not as a symmetric-encryption shortcut.
7. Investigate candidate novelty in the literature before naming a design contribution. New primitives require expert cryptanalysis and long scrutiny, not an unattended edit loop.

