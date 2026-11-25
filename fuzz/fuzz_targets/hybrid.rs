#![no_main]
// Arbitrary bytes into the hybrid layer's parsers: KEM public key, X-Wing ciphertext, sealed
// message, hybrid verifying key and signature. Must never panic. The decapsulation key and
// signer are fixed test keys. Any accepted signature or opened message would be a bug.
use libfuzzer_sys::fuzz_target;
use obsidian_research::hybrid::*;
use std::sync::OnceLock;

struct Fx { sk: KemSecret, vk: Vec<u8>, msg: Vec<u8> }
static FX: OnceLock<Fx> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let fx = FX.get_or_init(|| {
        let s = Signer::generate().unwrap();
        Fx { sk: KemSecret::from_seed([5; 32]), vk: s.verifying_key(), msg: b"m".to_vec() }
    });
    if data.is_empty() { return; }
    let sel = data[0] % 5;
    // Resize the payload to the exact valid length half the time, so inputs get past the
    // length checks and reach the real parsing code.
    let fit = |n: usize| -> Vec<u8> { let mut v = data[1..].to_vec(); v.resize(n, data[0]); v };
    let exact = data[0] & 0x80 != 0;
    let owned;
    let d: &[u8] = if exact {
        owned = match sel { 0 => fit(KEM_PK_LEN), 1 => fit(KEM_CT_TOTAL), 2 => fit(KEM_CT_TOTAL + 80), 3 => fit(SIG_LEN), _ => fit(VK_LEN) };
        &owned
    } else { &data[1..] };
    match sel {
        0 => { let _ = encapsulate(d); }
        1 => { let _ = fx.sk.decapsulate(d); }
        2 => { assert!(open_from(&fx.sk, d).is_err()); }
        3 => { assert!(verify(&fx.vk, &fx.msg, d).is_err()); }
        _ => { let _ = verify(d, &fx.msg, d); }
    }
});
