#![no_main]
// Envelope parsing with a valid-length key, plus a seal/open round trip for each mode.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let key = [7u8; 32];
    let _ = obsidian_research::open(&key, data);
    if let Some((&mode, rest)) = data.split_first() {
        let mode = mode % 3;
        let n = if mode == 2 { 12 } else { 24 };
        if rest.len() >= n {
            let (nonce, plain) = rest.split_at(n);
            if plain.len() <= obsidian_research::MAX {
                let env = obsidian_research::seal(mode, &key, nonce, plain).expect("valid inputs seal");
                assert_eq!(obsidian_research::open(&key, &env).expect("round trip"), plain);
            }
        }
    }
});
