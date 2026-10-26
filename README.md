# Obsidian

Rust cryptography research and a browser-local attack/test bench. Experimental, not audited, not for secrets.

The goal is serious research toward better encryption. Version R1 is a composition baseline built from existing primitives, not a claim of novelty, mathematical unbreakability, post-quantum superiority, or production readiness. Initial results lose to AES-256-GCM and XChaCha20-Poly1305 in bulk speed and envelope size. See research/SECURITY.md for the exact construction, assumptions, failures and proof obligations. research/ATTACKS.md retains attack findings and reproductions.

## Reproduce

Requires Rust, a C linker, and for the web build wasm-bindgen-cli 0.2.105.

```sh
cargo test --locked
cargo run --release --locked --example bench
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.105 --locked
cargo build --release --locked --target wasm32-unknown-unknown
wasm-bindgen target/wasm32-unknown-unknown/release/obsidian_research.wasm --target web --out-dir web/pkg
python3 -m http.server --directory web 8080 --bind 127.0.0.1
```

Open localhost:8080. The site has no backend or persistent storage. It needs HTTPS or localhost for secure browser randomness. Only generated non-secret keys and test messages belong here. Reviewers can run the entire source in an isolated directory. No real credentials, account access, cloud resources or private data are required by the bench. Native tests are deterministic. Benchmarks run locally and must be labeled by machine/compiler/flags, not treated as universal.

## Known failure

```sh
cargo test --locked reuse_exposes_plaintext_xor -- --nocapture
```

Shows recovery when the same key and nonce are reused, including in R1. UI generates nonces automatically; raw APIs cannot enforce uniqueness. This expected misuse failure is not fixed by R1. Surviving the other probes proves neither security nor absence of vulnerabilities.

## Files

- src/lib.rs: research construction and established baseline envelope implementations.
- tests/: roundtrip, malformed input, tamper, splice, parser and misuse probes.
- examples/bench.rs: same-task native encrypt/decrypt measurements.
- research/: design, threat model, analysis obligations and findings.
- evidence/: actual execution logs and single-run measurements.
- web/: static page, local WASM module and the same reports.

No external telemetry, no secrets in source, no CI/cloud spend, no server deployment included. Independent review and custom-subdomain deployment are separate gates.

Browser QA (requires Node, Python 3, Chrome): `npm ci --ignore-scripts && npm run test:web`. Set CHROME_PATH if Chrome is not at /usr/bin/google-chrome. Screenshots and a network/error/check receipt are written under evidence/. No external browser target is contacted by the test runner.
