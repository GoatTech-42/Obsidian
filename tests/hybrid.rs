#![cfg(all(feature = "pq-hybrid", not(target_arch = "wasm32")))]
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
    a[..32].copy_from_slice(&ct2[..32]);
    assert_ne!(sk.decapsulate(&a).map(|x| *x).ok(), Some(*k));
    let mut b = ct.clone();
    b[32..].copy_from_slice(&ct2[32..]);
    assert_ne!(sk.decapsulate(&b).map(|x| *x).ok(), Some(*k));
}

#[test]
fn low_order_x25519_point_rejected() {
    let sk = KemSecret::generate().unwrap();
    let (mut ct, _) = encapsulate(&sk.public_key()).unwrap();
    ct[..32].fill(0);
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
