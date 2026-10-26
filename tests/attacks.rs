use obsidian_research::{open, seal, MAX};
// Demonstrates the actual confidentiality failure if callers reuse a key+nonce.
#[test]
fn reuse_exposes_plaintext_xor() {
    for mode in 0..=2 {
        let n = if mode == 2 { 12 } else { 24 };
        let nonce = vec![8; n];
        let a = seal(mode, &[5; 32], &nonce, b"attack at dawn").unwrap();
        let b = seal(mode, &[5; 32], &nonce, b"retreat today!").unwrap();
        let recovered: Vec<u8> = a[8 + n..8 + n + 14]
            .iter()
            .zip(&b[8 + n..8 + n + 14])
            .zip(b"attack at dawn")
            .map(|((x, y), p)| x ^ y ^ p)
            .collect();
        assert_eq!(recovered, b"retreat today!");
    }
}
// Catches unexpected parser panics on attacker-controlled short byte strings.
#[test]
fn deterministic_parser_fuzz_no_panic() {
    let mut s = 73u64;
    for len in 0..512 {
        for _ in 0..8 {
            let mut v = vec![0; len];
            for x in &mut v {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                *x = s as u8;
            }
            assert!(open(&[2; 32], &v).is_err());
        }
    }
}
#[test]
fn input_cap_enforced() {
    for mode in 0..=2 {
        assert!(seal(
            mode,
            &[0; 32],
            &vec![0; if mode == 2 { 12 } else { 24 }],
            &vec![0; MAX + 1]
        )
        .is_err());
    }
}
// Any substitution of chunks from a different nonce must fail authentication.
#[test]
fn chosen_ciphertext_splice_and_mode_confusion() {
    for mode in 0..=2 {
        let n = if mode == 2 { 12 } else { 24 };
        let a = seal(mode, &[2; 32], &vec![1; n], &[11; 80]).unwrap();
        let b = seal(mode, &[2; 32], &vec![2; n], &[12; 80]).unwrap();
        let mut c = a.clone();
        c[8 + n..8 + n + 32].copy_from_slice(&b[8 + n..8 + n + 32]);
        assert!(open(&[2; 32], &c).is_err());
        for other in 0..=2 {
            if other != mode {
                let mut c = a.clone();
                c[4] = other;
                assert!(open(&[2; 32], &c).is_err());
            }
        }
    }
}
