//! Repeated benchmark runner. Each (mode, size, op) is its own job and gets its own row;
//! rows are never meant to be ranked across different jobs or modes.
//! Usage: cargo run --release --example bench_runs -- [runs]
use obsidian_research::{open, seal};
use std::{hint::black_box, time::Instant};

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    if n % 2 == 1 { v[n / 2] } else { (v[n / 2 - 1] + v[n / 2]) / 2.0 }
}

fn main() {
    let runs: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(9).max(1);
    println!("mode,op,bytes,runs,iterations,median_mib_s,min_mib_s,max_mib_s,spread_pct");
    for size in [64usize, 4096, 1048576] {
        for mode in 0..=2u8 {
            let iterations = if size == 1048576 { 12 } else { 200 };
            let data = vec![42u8; size];
            let key = [9u8; 32];
            let n = if mode == 2 { 12 } else { 24 };
            let envelope = seal(mode, &key, &vec![3; n], &data).unwrap();
            let mib = size as f64 * iterations as f64 / 1048576.0;
            for op in ["seal", "open"] {
                let mut rates = Vec::with_capacity(runs);
                for _ in 0..runs {
                    let start = Instant::now();
                    for i in 0..iterations {
                        if op == "seal" {
                            let mut nonce = vec![0u8; n];
                            nonce[..8].copy_from_slice(&(i as u64).to_be_bytes());
                            black_box(seal(mode, &key, &nonce, &data).unwrap());
                        } else {
                            black_box(open(&key, &envelope).unwrap());
                        }
                    }
                    rates.push(mib / start.elapsed().as_secs_f64());
                }
                let min = rates.iter().cloned().fold(f64::MAX, f64::min);
                let max = rates.iter().cloned().fold(0.0, f64::max);
                let med = median(&mut rates);
                println!("{mode},{op},{size},{runs},{iterations},{med:.3},{min:.3},{max:.3},{:.1}", (max - min) / med * 100.0);
            }
        }
    }
}
