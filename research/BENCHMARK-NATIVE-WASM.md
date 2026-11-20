# Native vs wasm benchmark (O1d)

Repeated runs of the same jobs on three paths. Each table below is one job (one
mode); rows are operation and payload size. Rows are only ever compared with the
same row on another path, never with another mode's rows, so there is no speed
ranking across cryptographic jobs. Performance only: no security claim of any kind.

## What was run

- Native: `bench_runs` (median, min, max and spread over 7 runs; 200 operations
  per run for 64 and 4096 bytes, 12 for 1 MiB). Each native CSV starts with the
  `envelope_digest` lines built under the same flags as the run:
  `{ cargo run -q --release --locked --example envelope_digest; cargo run -q --release --locked --example bench_runs -- 7; } > native_default.csv`
- Wasm: `cargo build --release --locked --target wasm32-unknown-unknown`, then
  `wasm-bindgen --target nodejs` (0.2.105) into a directory that also holds a
  `package.json` of `{"type":"commonjs"}`, and
  `node scripts/bench_wasm.mjs <dir> 7 > wasm_node.csv`, which prints its own digest lines first.
  Same key, payload, nonce scheme, iteration counts and CSV columns. Every call
  also copies key, nonce, payload and result across the JS/wasm boundary, and the
  wasm exports zeroize their input copies; those costs are part of the wasm row.
  Node runs wasm with V8, not a browser, and there is no warm-up, so early
  runs include JIT time.
- Same job check: `examples/envelope_digest.rs` and the first lines of
  `bench_wasm.mjs` print the SHA-256 of one fixed public test envelope per mode.
  `scripts/compare_native_wasm.py` refuses to join CSVs whose digests or rows differ, that lack a digest for any of modes 0, 1 and 2, that repeat a row or digest line, or whose runs or iterations differ for any joined (mode, op, bytes) row (`python3 scripts/test_compare_native_wasm.py` covers these; it is run by hand, not in CI).
  The digest check covers one fixed 64-byte test envelope per mode only, not every payload size that was timed.
  All three paths produced identical digests (so the same bytes are being sealed).
- Native armv8 AES: the same two commands with
  `RUSTFLAGS="--cfg aes_armv8 --cfg polyval_armv8 -C target-feature=+aes"` and a separate `--target-dir`,
  written to `native_armv8_aes.csv`.
  The aes and polyval crates used here enable their ARMv8 code only with those
  flags, so the default native build on this aarch64 host runs the portable
  code for AES-GCM. A build with `--cfg aes_force_soft --cfg polyval_force_soft --cfg chacha20_force_soft`
  gave the same medians as the default build, which confirms that. Only mode 2
  has a hardware-assisted path here.
- Join: `python3 scripts/compare_native_wasm.py native_default.csv native_armv8_aes.csv wasm_node.csv`
  gives `research/native-vs-wasm-aarch64.csv`.

## Exact flags for the measurement, and what is not recorded

Only the following is recorded in the repository. It comes from this file as
committed in 463bd85 (with the results) and 541e455, from `Cargo.toml` and from
the scripts. No shell log, build log or raw per-path CSV of the measurement is
committed, so these flags are as written down at the time, not independently
checkable from the repository.

- Release profile for every build (from `Cargo.toml`): `lto = true`,
  `codegen-units = 1`, `opt-level = 3`, built with `--locked`.
- Native default: no `RUSTFLAGS` recorded, so none beyond the defaults for the
  aarch64 Linux target.
- Native armv8 AES: `RUSTFLAGS="--cfg aes_armv8 --cfg polyval_armv8 -C target-feature=+aes"`,
  with a separate `--target-dir` (its path is not recorded).
- Wasm: `--target wasm32-unknown-unknown` with no `RUSTFLAGS` recorded, so no
  `+simd128` or other target features were requested; then `wasm-bindgen --target nodejs` 0.2.105.
- Runs and iterations: 7 runs (the `7` argument in the commands above);
  iterations per run as set in `examples/bench_runs.rs` and `scripts/bench_wasm.mjs`
  (200 for 64 and 4096 bytes, 12 for 1 MiB). The joined CSV does not carry
  the runs or iterations columns, so the committed table alone cannot show them.
- The earlier wording in 463bd85 gave the native command as
  `cargo run --release --locked --example bench_runs -- 7`; 541e455 rewrote it
  to the two-command form above. Both are descriptions written after the run.

PMULL: with `--cfg polyval_armv8`, polyval 0.6.2 (in `Cargo.lock`) compiles
its PMULL backend and picks it at run time when `cpufeatures` reports the
`aes` feature, which that crate treats as implying PMULL; aes 0.8.4 likewise
compiles its ARMv8 backend only under `--cfg aes_armv8`. Without those cfgs,
both crates use their portable code on aarch64. That much follows from the
crate sources. What the repository does not show: no disassembly, symbol check
or run-time log confirms that the armv8 build actually executed the PMULL or AES
instructions, and the timings do not separate AES from PMULL. The mode 2 speedup
of the armv8 build is consistent with hardware-assisted code being used, but how
much of it comes from PMULL (GHASH) versus AES instructions is unknown. The
"CPU flags include aes, pmull" line below and the `force_soft` comparison
mentioned above have no committed log or CSV behind them.

## Machine

As written in 463bd85; no committed log records these. aarch64 Linux sandbox, 2 vCPU (CPU flags include aes, pmull, sha2), 8 GiB RAM,
cargo 1.100.0, Node v22.23.5, wasm-bindgen 0.2.105. No pinning, no isolation, a
shared machine. The earlier x86_64 numbers in `web/benchmark.csv` are a different
machine and must not be mixed with these.

## Results (median MiB/s, spread = (max - min) / median over 7 runs)

### Mode 0 (R1)

| Op | Bytes | Native default | Native armv8 AES | Wasm in Node | Wasm / native default |
|---|---:|---:|---:|---:|---:|
| open | 64 | 12.9 (2.4%) | 13.0 (3.0%) | 8.5 (42.0%) | 0.66x |
| seal | 64 | 12.3 (3.4%) | 12.5 (2.1%) | 4.5 (108.3%) | 0.37x |
| open | 4096 | 34.0 (1.5%) | 33.9 (1.9%) | 28.4 (1.8%) | 0.83x |
| seal | 4096 | 33.6 (10.8%) | 33.9 (0.5%) | 28.1 (13.9%) | 0.84x |
| open | 1048576 | 34.6 (5.6%) | 34.8 (0.8%) | 30.2 (2.3%) | 0.87x |
| seal | 1048576 | 34.6 (1.0%) | 34.7 (1.1%) | 28.5 (7.6%) | 0.82x |

### Mode 1 (XChaCha20-Poly1305)

| Op | Bytes | Native default | Native armv8 AES | Wasm in Node | Wasm / native default |
|---|---:|---:|---:|---:|---:|
| open | 64 | 120.2 (27.1%) | 118.8 (5.9%) | 41.4 (76.0%) | 0.34x |
| seal | 64 | 100.3 (6.6%) | 99.5 (13.1%) | 14.0 (15.1%) | 0.14x |
| open | 4096 | 378.3 (0.7%) | 377.4 (1.6%) | 253.4 (33.8%) | 0.67x |
| seal | 4096 | 369.9 (51.0%) | 369.4 (2.6%) | 211.2 (24.0%) | 0.57x |
| open | 1048576 | 388.1 (0.8%) | 387.6 (3.6%) | 258.3 (11.6%) | 0.67x |
| seal | 1048576 | 383.8 (12.2%) | 370.2 (10.8%) | 217.7 (10.3%) | 0.57x |

### Mode 2 (AES-256-GCM)

| Op | Bytes | Native default | Native armv8 AES | Wasm in Node | Wasm / native default |
|---|---:|---:|---:|---:|---:|
| open | 64 | 30.6 (2.2%) | 196.2 (0.7%) | 8.5 (131.8%) | 0.28x |
| seal | 64 | 29.8 (3.1%) | 170.4 (10.0%) | 6.9 (87.4%) | 0.23x |
| open | 4096 | 113.7 (0.3%) | 1357.8 (1.6%) | 38.8 (10.7%) | 0.34x |
| seal | 4096 | 113.2 (2.2%) | 1251.0 (4.4%) | 37.7 (2.8%) | 0.33x |
| open | 1048576 | 118.6 (0.1%) | 1444.2 (1.1%) | 40.0 (1.7%) | 0.34x |
| seal | 1048576 | 118.1 (1.1%) | 1394.8 (5.3%) | 38.8 (1.3%) | 0.33x |

## Reading these numbers

- The 64-byte rows are noisy (for example wasm seal 64 in mode 0 has a 108.3%
  spread, and wasm open 64 in mode 2 has 131.8%).
- Spreads above about 10% (large for 64-byte rows and for some wasm rows) mean
  the median is only a rough guide on this shared machine. Treat ratios from
  such rows as indicative at best.
- Compare a row only with the same row on another path. Mode 0, 1 and 2 are
  different cryptographic jobs with different primitives and envelope sizes.
- Not measured here: browser engines, memory use, code size, wasm SIMD, an
  x86_64 host. Wasm numbers are from Node on aarch64, so they say nothing
  about a particular browser.
