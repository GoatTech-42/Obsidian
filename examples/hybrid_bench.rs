//! Timing and size of the hybrid layer. Single machine, single run; label results by machine.
use obsidian_research::hybrid::*;
use std::time::Instant;
fn t<F: FnMut()>(name: &str, n: u32, mut f: F) {
    f();
    let s = Instant::now();
    for _ in 0..n { f(); }
    println!("{name},{:.1}us", s.elapsed().as_secs_f64() * 1e6 / n as f64);
}
fn main() {
    println!("sizes: kem_pk={KEM_PK_LEN} kem_ct={KEM_CT_TOTAL} sig={SIG_LEN} vk={VK_LEN}");
    let sk = KemSecret::generate().unwrap();
    let pk = sk.public_key();
    let (ct, _) = encapsulate(&pk).unwrap();
    let s = Signer::generate().unwrap();
    let vk = s.verifying_key();
    let sig = s.sign(b"m").unwrap();
    t("kem_keygen+pubkey", 200, || { KemSecret::generate().unwrap().public_key(); });
    t("encapsulate", 500, || { encapsulate(&pk).unwrap(); });
    t("decapsulate", 500, || { sk.decapsulate(&ct).unwrap(); });
    t("sign_keygen+vk", 100, || { Signer::generate().unwrap().verifying_key(); });
    t("sign", 200, || { s.sign(b"m").unwrap(); });
    t("verify", 500, || { verify(&vk, b"m", &sig).unwrap(); });
}
