#![no_main]
// Arbitrary key and envelope bytes into open(). Must never panic; any Ok result must be
// within the documented size bound.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let split = data.len().min(32);
    let (key, envelope) = data.split_at(split);
    if let Ok(plain) = obsidian_research::open(key, envelope) {
        assert!(plain.len() <= obsidian_research::MAX);
    }
});
