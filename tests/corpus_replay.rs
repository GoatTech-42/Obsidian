// Replays the minimized fuzz corpus (tests/corpus/<target>) through the same logic as the
// fuzz targets in fuzz/fuzz_targets, on the stable toolchain. A regression test, not a
// security claim.
use std::fs;
use std::path::Path;

fn files(target: &str) -> Vec<Vec<u8>> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus").join(target);
    let mut names: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("corpus dir {}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .collect();
    names.sort();
    names.iter().map(|p| fs::read(p).unwrap()).collect()
}

#[test]
fn replay_decrypt() {
    let inputs = files("decrypt");
    assert!(!inputs.is_empty(), "decrypt corpus is empty");
    for data in &inputs {
        let (key, envelope) = data.split_at(data.len().min(32));
        if let Ok(plain) = obsidian_research::open(key, envelope) {
            assert!(plain.len() <= obsidian_research::MAX);
        }
    }
}

#[test]
fn replay_parse() {
    let inputs = files("parse");
    assert!(!inputs.is_empty(), "parse corpus is empty");
    let key = [7u8; 32];
    for data in &inputs {
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
    }
}
