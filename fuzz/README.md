# Fuzz targets

Two cargo-fuzz targets over the raw `open`/`seal` API: `decrypt` (arbitrary key and envelope bytes) and `parse` (envelope parsing with a fixed-length key, plus a seal/open round trip per mode). They check for panics and round-trip failures only; this is not a security claim.

    cargo install cargo-fuzz --locked
    cd fuzz && cargo +nightly fuzz run decrypt -- -max_total_time=60 -max_len=2048

Keep local runs time-boxed. The corpus is not committed yet.
