use obsidian_research::{open, seal, Error};
// Catches a missing encryption/decryption path, truncation and wrong byte handling.
#[test]
fn all_modes_roundtrip_binary_and_empty() {
    for mode in 0..=2 {
        let nonce = vec![7; if mode == 2 { 12 } else { 24 }];
        for data in [
            vec![],
            vec![0, 255, 128, 1],
            "ferrets cannot solve this with a substitution table"
                .as_bytes()
                .to_vec(),
            vec![42; 1025],
        ] {
            let e = seal(mode, &[3; 32], &nonce, &data).unwrap();
            assert_eq!(open(&[3; 32], &e).unwrap(), data);
        }
    }
}
// Catches missing authentication of the header, nonce, payload, or tag.
#[test]
fn every_byte_tamper_is_rejected() {
    for mode in 0..=2 {
        let e = seal(
            mode,
            &[3; 32],
            &vec![7; if mode == 2 { 12 } else { 24 }],
            b"test tamper",
        )
        .unwrap();
        for i in 0..e.len() {
            let mut bad = e.clone();
            bad[i] ^= 1;
            assert!(open(&[3; 32], &bad).is_err(), "mode {mode}, byte {i}");
        }
        assert!(open(&[4; 32], &e).is_err());
        for n in 0..e.len() {
            assert!(open(&[3; 32], &e[..n]).is_err());
        }
        let mut extra = e;
        extra.push(0);
        assert!(open(&[3; 32], &extra).is_err());
    }
}
// Catches acceptance of bad key sizes, bad modes and nonces.
#[test]
fn malformed_inputs_fail_closed() {
    assert_eq!(seal(0, &[0; 31], &[0; 24], b"a"), Err(Error::InvalidKey));
    assert_eq!(seal(0, &[0; 32], &[0; 23], b"a"), Err(Error::InvalidNonce));
    assert_eq!(
        seal(3, &[0; 32], &[0; 24], b"a"),
        Err(Error::InvalidEnvelope)
    );
    assert_eq!(open(&[0; 31], &[]), Err(Error::InvalidKey));
}
// Catches accidental nonce omission and payload lengths that drift with mode.
#[test]
fn nonce_changes_ciphertext_and_lengths_match_spec() {
    for mode in 0..=2 {
        let n = if mode == 2 { 12 } else { 24 };
        let a = seal(mode, &[1; 32], &vec![0; n], b"abc").unwrap();
        let b = seal(mode, &[1; 32], &vec![1; n], b"abc").unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), 8 + n + 3 + if mode == 0 { 32 } else { 16 });
    }
}

// Independently derived Python stdlib fixture catches stream/HKDF/layout drift.
#[test]
fn independent_r1_reference_vector() {
    let expected="4f42533100000000070707070707070707070707070707070707070707070707d880601f3d32722cc6f06dc3c13af599add87afa8e8f527bde2fab39d612a020cdf1e4ed3bc5f813af8a2cc068c82c01d3c727b56178403799";
    let got = seal(0, &[3; 32], &[7; 24], b"Obsidian reference vector").unwrap();
    let hex: String = got.iter().map(|x| format!("{x:02x}")).collect();
    assert_eq!(hex, expected);
}

// Independent Python cryptography AESGCM fixture, not our implementation.
#[test]
fn independent_aes_reference_vector() {
    let got = seal(2, &[3; 32], &[7; 12], b"Obsidian AES independent vector").unwrap();
    let hex: String = got.iter().map(|x| format!("{x:02x}")).collect();
    assert_eq!(hex,"4f425331020000000707070707070707070707075b4fb7ca7001fbcb1adf3eb0077fca912b8e06eb9fac856b6aaeb673d732f4a97081612611d08eb191d0cf2f3758d9");
}
