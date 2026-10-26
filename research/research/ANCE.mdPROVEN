# Research provenance

Official standards/specs read via their published pages on 2026-10-26. Rust dependency versions are pinned in Cargo.toml and exact resolved graph in Cargo.lock. Historical RustCrypto audit discussions establish only historical scope, not an audit of this application or today's exact versions. No audit badge is warranted.

Source ledger:
- Shannon 1949 primary research: https://www.cs.virginia.edu/~evans/greatworks/shannon1949.pdf ; section 10 for perfect secrecy and key-space restriction.
- IETF primary specification RFC 2104: https://www.rfc-editor.org/rfc/rfc2104 ; HMAC construction, computational assumptions.
- IETF primary specification RFC 5869: https://www.rfc-editor.org/rfc/rfc5869 ; extraction/expansion/domain context, not password hardening.
- IETF primary specification RFC 8439: https://www.rfc-editor.org/rfc/rfc8439 ; authenticated encryption, uniqueness requirement and security considerations.
- NIST primary standards: https://csrc.nist.gov/pubs/fips/203/final and https://csrc.nist.gov/Projects/Post-Quantum-Cryptography ; separate KEM/signature roles, current conditional security framing.
- Library primary API docs: https://docs.rs/chacha20poly1305/latest/chacha20poly1305/ and https://docs.rs/hkdf/latest/hkdf/ ; construction description/API and caveats, not proof of our composition.
- Independent historical audit discussion: https://github.com/RustCrypto/AEADs/issues/87 ; limited historical context only, never transferred as present audit coverage.

Technical sources are primary research, standards and library documentation. General user reviews are not evidence of cryptographic security and were intentionally not substituted for those sources.
