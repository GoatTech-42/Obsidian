use obsidian_research::{open, seal};
use std::{hint::black_box, time::Instant};
fn main() {
    println!("mode,bytes,iterations,seal_mib_s,open_mib_s,envelope_overhead_bytes");
    for size in [64, 4096, 1048576] {
        for mode in 0..=2 {
            let iterations = if size == 1048576 { 12 } else { 200 };
            let data = vec![42; size];
            let key = [9; 32];
            let n = if mode == 2 { 12 } else { 24 };
            let start = Instant::now();
            for i in 0..iterations {
                let mut nonce = vec![0; n];
                nonce[..8].copy_from_slice(&(i as u64).to_be_bytes());
                black_box(seal(mode, &key, &nonce, &data).unwrap());
            }
            let enc = start.elapsed().as_secs_f64();
            let envelope = seal(mode, &key, &vec![3; n], &data).unwrap();
            let start = Instant::now();
            for _ in 0..iterations {
                black_box(open(&key, &envelope).unwrap());
            }
            let dec = start.elapsed().as_secs_f64();
            let mib = size as f64 * iterations as f64 / 1048576.0;
            println!(
                "{mode},{size},{iterations},{:.3},{:.3},{}",
                mib / enc,
                mib / dec,
                envelope.len() - size
            );
        }
    }
}
