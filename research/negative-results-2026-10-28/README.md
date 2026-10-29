# Negative research checkpoint, 2026-10-28

Toy-width measurements for Obsidian research. This is NOT a new cipher, not a security claim, and not part of the live demo. No design here is better than AES or ChaCha.

- scripts/clus.py, clus3.py, clus4.py: exact key-averaged differential probability vs best single trail on a small key-alternating model (3-bit S-boxes, 9/12-bit state, independent round keys). clus3/clus4 are matrix-free; clus4 takes an alternate 3-bit S-box.
- scripts/k1.py: a cube-over-GF(2^n) Feistel (n=5 only). Rejected: same structure as a cipher already attacked in the literature (Jakobsen-Knudsen, FSE 1997).
- notes/: results for S-box 1 (x^3 over GF(8), APN) and S-box 2 (one random max-DP-1/2 permutation), plus raw tables.

Result in one line: with the APN S-box and a weak bit-permutation layer, the real maximum differential probability exceeds the best-trail figure by several times at middle rounds; one second S-box does not reproduce that gap at matched rounds. Observed, not proved; independent-key model; no claim about full width.
