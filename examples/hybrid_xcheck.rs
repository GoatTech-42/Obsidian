//! Cross-implementation check helper. `emit` prints fresh keys, a KEM encapsulation and a
//! signature as JSON. `decap SK_HEX CT_HEX` prints the shared secret. Test keys only.
use obsidian_research::hybrid::*;
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
fn unhex(s: &str) -> Vec<u8> { (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect() }
fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.get(1).map(String::as_str) == Some("decap") {
        let sk = KemSecret::from_seed(unhex(&a[2]).try_into().unwrap());
        println!("{}", hex(&*sk.decapsulate(&unhex(&a[3])).unwrap()));
        return;
    }
    let mut seed = [0u8; 32];
    for (i, b) in seed.iter_mut().enumerate() { *b = (i as u8).wrapping_mul(7).wrapping_add(rand_byte()); }
    let sk = KemSecret::from_seed(seed);
    let pk = sk.public_key();
    let (ct, ss) = encapsulate(&pk).unwrap();
    let s = Signer::generate().unwrap();
    let msg = b"cross-check message";
    println!("{{\"sk\":\"{}\",\"pk\":\"{}\",\"ct\":\"{}\",\"ss\":\"{}\",\"vk\":\"{}\",\"msg\":\"{}\",\"sig\":\"{}\"}}",
        hex(&seed), hex(&pk), hex(&ct), hex(&*ss), hex(&s.verifying_key()), hex(msg), hex(&s.sign(msg).unwrap()));
}
fn rand_byte() -> u8 { let mut b = [0u8; 1]; std::fs::File::open("/dev/urandom").and_then(|mut f| std::io::Read::read_exact(&mut f, &mut b)).unwrap(); b[0] }
