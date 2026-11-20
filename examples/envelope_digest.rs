//! Prints the SHA-256 of one fixed, public test envelope per mode. The native and wasm
//! benchmark runs must print identical digests, so both time the same job.
//! Usage: cargo run --release --example envelope_digest
use obsidian_research::seal;
use sha2::{Digest, Sha256};

fn main() {
    let data = vec![42u8; 64];
    let key = [9u8; 32];
    for mode in 0..=2u8 {
        let n = if mode == 2 { 12 } else { 24 };
        let envelope = seal(mode, &key, &vec![3; n], &data).unwrap();
        let hex: String = Sha256::digest(&envelope).iter().map(|b| format!("{b:02x}")).collect();
        println!("digest,{mode},{hex}");
    }
}
