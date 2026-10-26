# Independent attack harnesses - Obsidian R1 review round 1 (2026-10-26, rev 2)

Reviewer-executed, independent of builder cargo runs (no Rust toolchain on reviewer side;
all dynamic attacks run against the actual deployment-candidate WASM via node 22).

## Bytes under attack
- lib.rs sha256 3b334e1e11787ba53afe3f91323979b1f5791ca39f6bc2a7b67e7f481cc3a826 (v3)
- web/app.js sha256 ba6b190fbc15ea01a0b6e2a3407106a12812429c88a53ceb9df1a9943b11b851
- deployment-candidate WASM sha256 a29f5d87bb1ee5b255cfda5ca73c4581cc6e07483f0b9884fa36f92e2486881f

## Harnesses (node 22; usage: PKG=<path to web/pkg> node <file>; exit 1 on any FAIL)
- h1-v3.mjs - all-mode roundtrips; every-byte tamper + EVERY truncation + extension across
  all modes (377 cases exactly counted); nonce-reuse XOR leak + known-plaintext recovery in
  ALL THREE modes; 15 malformed-open probes; 1 MiB / 1 MiB+1 / empty boundaries;
  reserved-byte / bad-mode / wrong-key rejects.
- h2-v3.mjs - independent AES-256-GCM KAT via WebCrypto; 4000-case random fuzz (half with
  correct OBS1 magic to exercise deep-parse paths); 2000-case structured corruption.
- r1_kat.py - independent R1 known-answer derivation in pure Python stdlib (HKDF-expand,
  HMAC keystream, encrypt-then-MAC) from the SECURITY.md spec only.

## Results (reviewer runs against the deployment-candidate wasm)
- Tamper/truncation/extension: 0 accepted of 377. Expected reject-all; observed reject-all.
- Fuzz 6000 cases: 0 accepted, 0 panics. Parser fails closed, never traps.
- AES-GCM fixture and R1 vector: both independently reproduced byte-identical.

## KNOWN FINDING REPRODUCED (accepted limitation, not new)
- Key+nonce reuse, ALL THREE MODES: C1^C2 == P1^P2 byte-exact; full second-plaintext
  recovery from known first plaintext. Impact: catastrophic on misuse. Shipped mitigations:
  UI never lets callers set the nonce; prominent disclosure. Fix direction: SIV / GCM-SIV
  nonce-misuse-resistant comparison (next research round). Retest: h1-v3.mjs reuse cases.

## Rev 2 corrections to the rev-1 harnesses (reviewer-owned defects)
- Case counter now counts every truncation case (rev 1 undercounted totals; reject
  conclusions unaffected - accepted counts were exact).
- Random-fuzz magic constant fixed to OBS1 (rev 1 used OBSI; the intended deep-parse branch
  never ran in rev 1's random fuzz - covered anyway by structured fuzz and tamper suites;
  rev 2 random fuzz genuinely exercises it, still 0 accepted / 0 panics).
- Nonce-reuse recovery now executed for all three modes (rev 1 executed mode 0 only).
- Paths are PKG-relative; exit code is nonzero on any FAIL; no dependency on earlier builds.

## New findings: none this round. Absence of findings is not absence of vulnerabilities;
the R1 composition's CCA reduction remains unproved per SECURITY.md.

From repository root: PKG="$PWD/web/pkg" node research/independent/h1-v3.mjs, then h2-v3.mjs; python3 research/independent/r1_kat.py. Historical wording referred to the deployment candidate, not a live public website.
