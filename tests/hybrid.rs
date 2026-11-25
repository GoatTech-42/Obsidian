#![cfg(all(feature = "xwing-derand", not(target_arch = "wasm32")))]
//! Tests for the hybrid layer. NIST ACVP vectors check the ML-KEM-768 and ML-DSA-65 crates
//! on this machine. The hybrid wiring tests check that our combination behaves.
use ml_kem::{kem::Decapsulate, Ciphertext, DecapsulationKey, EncapsulationKey, KeyExport, MlKem768};
use obsidian_research::hybrid::*;
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/acvp-mlkem768-mldsa65.json")).unwrap()
}
fn hx(v: &Value, k: &str) -> Vec<u8> {
    let s = v[k].as_str().unwrap();
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

#[test]
fn acvp_mlkem768_encapsulation() {
    let v = vectors();
    let t = v["encap"].as_array().unwrap();
    assert_eq!(t.len(), 25);
    for c in t {
        let ek = EncapsulationKey::<MlKem768>::new(&ml_kem::Key::<EncapsulationKey<MlKem768>>::try_from(&hx(c, "ek")[..]).unwrap()).unwrap();
        let m = ml_kem::B32::try_from(&hx(c, "m")[..]).unwrap();
        let (ct, k) = ek.encapsulate_deterministic(&m);
        assert_eq!(ct.as_slice(), &hx(c, "c")[..]);
        assert_eq!(k.as_slice(), &hx(c, "k")[..]);
    }
}

#[test]
#[allow(deprecated)]
fn acvp_mlkem768_decapsulation() {
    let v = vectors();
    let t = v["decap"].as_array().unwrap();
    assert_eq!(t.len(), 10);
    for c in t {
        let dk = DecapsulationKey::<MlKem768>::from_expanded(&ml_kem::ExpandedDecapsulationKey::<MlKem768>::try_from(&hx(c, "dk")[..]).unwrap()).unwrap();
        let ct = Ciphertext::<MlKem768>::try_from(&hx(c, "c")[..]).unwrap();
        assert_eq!(dk.decapsulate(&ct).as_slice(), &hx(c, "k")[..]);
    }
}

#[test]
fn acvp_mlkem768_keygen() {
    let v = vectors();
    let t = v["keygen"].as_array().unwrap();
    assert_eq!(t.len(), 25);
    for c in t {
        let mut seed = hx(c, "d");
        seed.extend(hx(c, "z"));
        let dk = DecapsulationKey::<MlKem768>::from_seed(ml_kem::Seed::try_from(&seed[..]).unwrap());
        assert_eq!(dk.encapsulation_key().to_bytes().as_slice(), &hx(c, "ek")[..]);
    }
}

#[test]
fn acvp_mldsa65_sigver() {
    use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};
    let v = vectors();
    let (mut pass, mut fail) = (0, 0);
    for (name, internal) in [("sigver_pure", false), ("sigver_internal", true)] {
        for c in v[name].as_array().unwrap() {
            let vk = VerifyingKey::<MlDsa65>::decode(&EncodedVerifyingKey::<MlDsa65>::try_from(&hx(c, "pk")[..]).unwrap());
            let sig = EncodedSignature::<MlDsa65>::try_from(&hx(c, "signature")[..]).ok().and_then(|s| Signature::<MlDsa65>::decode(&s));
            let got = match sig {
                None => false,
                Some(s) if internal => vk.verify_internal(&hx(c, "message"), &s),
                Some(s) => vk.verify_with_context(&hx(c, "message"), &hx(c, "context"), &s),
            };
            assert_eq!(got, c["ok"].as_bool().unwrap(), "{name} vector mismatch");
            if got { pass += 1 } else { fail += 1 }
        }
    }
    assert!(pass > 0 && fail > 0, "need both accept and reject vectors");
}

#[test]
fn kem_roundtrip_and_sizes() {
    let sk = KemSecret::generate().unwrap();
    let pk = sk.public_key();
    assert_eq!(pk.len(), KEM_PK_LEN);
    let (ct, k1) = encapsulate(&pk).unwrap();
    assert_eq!(ct.len(), KEM_CT_TOTAL);
    assert_eq!(*sk.decapsulate(&ct).unwrap(), *k1);
}

#[test]
fn seal_open_all_modes_and_tamper() {
    let sk = KemSecret::generate().unwrap();
    let pk = sk.public_key();
    for mode in 0..=2 {
        let m = seal_to(&pk, mode, b"hello hybrid").unwrap();
        assert_eq!(open_from(&sk, &m).unwrap(), b"hello hybrid");
        for i in (0..m.len()).step_by(37).chain([m.len() - 1]) {
            let mut bad = m.clone();
            bad[i] ^= 1;
            assert!(open_from(&sk, &bad).is_err(), "mode {mode} byte {i} tamper accepted");
        }
        assert!(open_from(&sk, &m[..m.len() - 1]).is_err());
    }
}

#[test]
fn wrong_recipient_fails() {
    let a = KemSecret::generate().unwrap();
    let b = KemSecret::generate().unwrap();
    let m = seal_to(&a.public_key(), 1, b"x").unwrap();
    assert!(open_from(&b, &m).is_err());
}

#[test]
fn both_kem_halves_are_bound_into_the_key() {
    // Replace either half of the ciphertext: the derived key must change.
    let sk = KemSecret::generate().unwrap();
    let (ct, k) = encapsulate(&sk.public_key()).unwrap();
    let (ct2, _) = encapsulate(&sk.public_key()).unwrap();
    let mut a = ct.clone();
    a[KEM_CT_LEN..].copy_from_slice(&ct2[KEM_CT_LEN..]);
    assert_ne!(sk.decapsulate(&a).map(|x| *x).ok(), Some(*k));
    let mut b = ct.clone();
    b[..KEM_CT_LEN].copy_from_slice(&ct2[..KEM_CT_LEN]);
    assert_ne!(sk.decapsulate(&b).map(|x| *x).ok(), Some(*k));
}

#[test]
fn low_order_x25519_point_rejected() {
    let sk = KemSecret::generate().unwrap();
    let (mut ct, _) = encapsulate(&sk.public_key()).unwrap();
    ct[KEM_CT_LEN..].fill(0);
    assert_eq!(sk.decapsulate(&ct).err(), Some(HybridError::WeakPoint));
}

#[test]
fn signature_needs_both_halves() {
    let s = Signer::generate().unwrap();
    let vk = s.verifying_key();
    assert_eq!(vk.len(), VK_LEN);
    let sig = s.sign(b"release 1.0").unwrap();
    assert_eq!(sig.len(), SIG_LEN);
    verify(&vk, b"release 1.0", &sig).unwrap();
    assert!(verify(&vk, b"release 1.1", &sig).is_err());
    let mut ed_bad = sig.clone();
    ed_bad[3] ^= 1;
    assert!(verify(&vk, b"release 1.0", &ed_bad).is_err(), "ed25519 half must be required");
    let mut dsa_bad = sig.clone();
    dsa_bad[100] ^= 1;
    assert!(verify(&vk, b"release 1.0", &dsa_bad).is_err(), "ml-dsa half must be required");
    let other = Signer::generate().unwrap();
    assert!(verify(&other.verifying_key(), b"release 1.0", &sig).is_err());
}

#[test]
fn xwing_draft11_official_vectors() {
    // draft-connolly-cfrg-xwing-kem-11 Appendix C / spec/test-vectors.json (3 vectors).
    let v: Value = serde_json::from_str(include_str!("vectors/xwing-draft11.json")).unwrap();
    let v = v.as_array().unwrap();
    assert_eq!(v.len(), 3);
    for c in v {
        let seed: [u8; 32] = hx(c, "seed").try_into().unwrap();
        let sk = KemSecret::from_seed(seed);
        assert_eq!(sk.public_key(), hx(c, "pk"), "public key from seed");
        let eseed: [u8; 64] = hx(c, "eseed").try_into().unwrap();
        let (ct, ss) = encapsulate_derand(&hx(c, "pk"), &eseed).unwrap();
        assert_eq!(ct, hx(c, "ct"), "ciphertext");
        assert_eq!(ss.as_slice(), &hx(c, "ss")[..], "encapsulated shared secret");
        assert_eq!(sk.decapsulate(&hx(c, "ct")).unwrap().as_slice(), &hx(c, "ss")[..], "decapsulated shared secret");
    }
}

#[test]
fn malformed_inputs_never_panic() {
    let sk = KemSecret::generate().unwrap();
    let pk = sk.public_key();
    let s = Signer::generate().unwrap();
    let vk = s.verifying_key();
    let sig = s.sign(b"m").unwrap();
    // Wrong lengths, truncations, all-zero and all-ff inputs, and a few thousand pseudo-random mutations.
    for n in [0usize, 1, 31, 32, 33, KEM_CT_TOTAL - 1, KEM_CT_TOTAL, KEM_CT_TOTAL + 1, 4000] {
        for fill in [0u8, 0xff] {
            let b = vec![fill; n];
            let _ = sk.decapsulate(&b);
            let _ = open_from(&sk, &b);
            let _ = encapsulate(&b);
            let _ = verify(&b, b"m", &sig);
            let _ = verify(&vk, b"m", &b);
        }
    }
    let mut x: u64 = 0x9e3779b97f4a7c15;
    let mut next = || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
    let good = seal_to(&pk, 1, b"payload").unwrap();
    for _ in 0..2000 {
        let mut m = good.clone();
        for _ in 0..(1 + next() % 4) { let i = (next() as usize) % m.len(); m[i] ^= (next() % 255 + 1) as u8; }
        assert!(open_from(&sk, &m).is_err(), "mutated message accepted");
        let mut g = sig.clone();
        let i = (next() as usize) % g.len();
        g[i] ^= (next() % 255 + 1) as u8;
        assert!(verify(&vk, b"m", &g).is_err(), "mutated signature accepted");
    }
}
