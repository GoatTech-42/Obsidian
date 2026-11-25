//! Hybrid classical + post-quantum key establishment and signatures for Obsidian.
//!
//! Built only from existing, standardized primitives through the RustCrypto crates
//! `ml-kem` (FIPS 203, ML-KEM-768), `ml-dsa` (FIPS 204, ML-DSA-65), `x25519-dalek`,
//! `ed25519-dalek`, `sha3` and `shake`. Nothing here is a new primitive.
//!
//! KEM: this is X-Wing exactly as written in draft-connolly-cfrg-xwing-kem-11
//! (X25519 + ML-KEM-768, SHA3-256 combiner, 32-byte decapsulation key expanded with
//! SHAKE256). The X-Wing paper (https://eprint.iacr.org/2024/039) proves it IND-CCA
//! secure if either X25519 (strong DH, ROM) or ML-KEM-768 is secure. The draft is an
//! Independent Submission Internet-Draft, not an RFC or a NIST standard. We do not
//! change it. Output matches the draft's published test vectors (tests/hybrid.rs).
//!
//! Signatures: Ed25519 + ML-DSA-65, BOTH must verify. This combination is our own
//! simple "AND" wiring (no standard, no proof written for it beyond the argument in
//! research/POST-QUANTUM.md).
//!
//! Not independently audited. The underlying crates state they are unaudited. Obsidian's
//! own cipher is not what makes this layer post-quantum: a 256-bit symmetric key is
//! already out of reach of known quantum attacks, the quantum-exposed parts are key
//! exchange and signatures, and those come from ML-KEM and ML-DSA here.
use crate::{open, seal, Error};
use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey};
use ml_dsa::{MlDsa65, SigningKey as DsaSigningKey, VerifyingKey as DsaVerifyingKey};
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    Ciphertext, DecapsulationKey, EncapsulationKey, KeyExport, MlKem768, Seed as KemSeed,
};
use sha3::{Digest, Sha3_256};
use shake::digest::{ExtendableOutput, Update, XofReader};
use zeroize::Zeroizing;

pub const KEM_EK_LEN: usize = 1184;
pub const KEM_CT_LEN: usize = 1088;
pub const DSA_VK_LEN: usize = 1952;
pub const DSA_SIG_LEN: usize = 3309;
pub const ED_SIG_LEN: usize = 64;
/// X-Wing encapsulation key: ml-kem-768 encapsulation key(1184) || x25519(32).
pub const KEM_PK_LEN: usize = KEM_EK_LEN + 32;
/// X-Wing ciphertext: ml-kem-768 ciphertext(1088) || ephemeral x25519(32).
pub const KEM_CT_TOTAL: usize = KEM_CT_LEN + 32;
/// Signature: ed25519(64) || ml-dsa-65(3309).
pub const SIG_LEN: usize = ED_SIG_LEN + DSA_SIG_LEN;
/// Verifying key: ed25519(32) || ml-dsa-65(1952).
pub const VK_LEN: usize = 32 + DSA_VK_LEN;

/// "\./" "/^\" = 5c2e2f2f5e5c
const XWING_LABEL: [u8; 6] = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];
const SIG_CTX: &[u8] = b"Obsidian/hybrid-sig/v1";

#[derive(Debug, PartialEq)]
pub enum HybridError {
    Random,
    InvalidKey,
    InvalidCiphertext,
    /// X25519 produced the all-zero output (low-order point). The X-Wing draft does not
    /// require this check; we add it as a stricter local policy.
    WeakPoint,
    InvalidSignature,
    Envelope(Error),
}

fn rand<const N: usize>() -> Result<Zeroizing<[u8; N]>, HybridError> {
    let mut b = Zeroizing::new([0u8; N]);
    getrandom4::fill(&mut *b).map_err(|_| HybridError::Random)?;
    Ok(b)
}

fn x25519_pub(sk: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*sk, x25519_dalek::X25519_BASEPOINT_BYTES)
}

/// X-Wing Combiner(ss_M, ss_X, ct_X, pk_X) = SHA3-256(ss_M || ss_X || ct_X || pk_X || label)
fn combiner(ss_m: &[u8], ss_x: &[u8; 32], ct_x: &[u8; 32], pk_x: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut buf = Zeroizing::new(Vec::with_capacity(32 * 4 + 6));
    buf.extend_from_slice(ss_m);
    buf.extend_from_slice(ss_x);
    buf.extend_from_slice(ct_x);
    buf.extend_from_slice(pk_x);
    buf.extend_from_slice(&XWING_LABEL);
    Zeroizing::new(Sha3_256::digest(&*buf).into())
}

/// Long-term X-Wing decapsulation key: the 32-byte seed (draft section 5.2).
pub struct KemSecret {
    sk: Zeroizing<[u8; 32]>,
}

/// expandDecapsulationKey: SHAKE256(sk, 96) -> ML-KEM seed (64) || x25519 secret (32).
fn expand(sk: &[u8; 32]) -> (DecapsulationKey<MlKem768>, Zeroizing<[u8; 32]>, [u8; 32]) {
    let mut xof = shake::Shake256::default();
    xof.update(sk);
    let mut r = xof.finalize_xof();
    let mut buf = Zeroizing::new([0u8; 96]);
    r.read(&mut *buf);
    let dk = DecapsulationKey::<MlKem768>::from_seed(KemSeed::try_from(&buf[..64]).expect("64 bytes"));
    let sk_x = Zeroizing::new(<[u8; 32]>::try_from(&buf[64..]).expect("32 bytes"));
    let pk_x = x25519_pub(&sk_x);
    (dk, sk_x, pk_x)
}

impl KemSecret {
    pub fn generate() -> Result<Self, HybridError> {
        Ok(Self { sk: rand::<32>()? })
    }
    /// Deterministic key from a 32-byte seed (GenerateKeyPairDerand). Use only for tests.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { sk: Zeroizing::new(seed) }
    }
    /// 1216-byte public key: pk_M || pk_X.
    pub fn public_key(&self) -> Vec<u8> {
        let (dk, _, pk_x) = expand(&self.sk);
        let mut pk = dk.encapsulation_key().to_bytes().to_vec();
        pk.extend_from_slice(&pk_x);
        pk
    }
    /// Recover the 32-byte shared key from a 1120-byte X-Wing ciphertext.
    /// A tampered ML-KEM part gives a different key (ML-KEM implicit rejection), not an error.
    pub fn decapsulate(&self, ct: &[u8]) -> Result<Zeroizing<[u8; 32]>, HybridError> {
        if ct.len() != KEM_CT_TOTAL {
            return Err(HybridError::InvalidCiphertext);
        }
        let ct_x: [u8; 32] = ct[KEM_CT_LEN..].try_into().unwrap();
        let (dk, sk_x, pk_x) = expand(&self.sk);
        let ss_x = Zeroizing::new(x25519_dalek::x25519(*sk_x, ct_x));
        if ss_x.iter().all(|b| *b == 0) {
            return Err(HybridError::WeakPoint);
        }
        let c = Ciphertext::<MlKem768>::try_from(&ct[..KEM_CT_LEN]).map_err(|_| HybridError::InvalidCiphertext)?;
        let ss_m = dk.decapsulate(&c);
        Ok(combiner(ss_m.as_slice(), &ss_x, &ct_x, &pk_x))
    }
}

fn parse_pk(pk: &[u8]) -> Result<(EncapsulationKey<MlKem768>, [u8; 32]), HybridError> {
    if pk.len() != KEM_PK_LEN {
        return Err(HybridError::InvalidKey);
    }
    let key = ml_kem::Key::<EncapsulationKey<MlKem768>>::try_from(&pk[..KEM_EK_LEN]).map_err(|_| HybridError::InvalidKey)?;
    let ek = EncapsulationKey::<MlKem768>::new(&key).map_err(|_| HybridError::InvalidKey)?;
    Ok((ek, pk[KEM_EK_LEN..].try_into().unwrap()))
}

/// Encapsulate to a public key. Returns (1120-byte ciphertext, 32-byte shared key).
pub fn encapsulate(pk: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), HybridError> {
    let (ek, pk_x) = parse_pk(pk)?;
    let (ct_m, ss_m) = ek.encapsulate();
    let esk = rand::<32>()?;
    let ct_x = x25519_pub(&esk);
    let ss_x = Zeroizing::new(x25519_dalek::x25519(*esk, pk_x));
    if ss_x.iter().all(|b| *b == 0) {
        return Err(HybridError::WeakPoint);
    }
    let mut ct = ct_m.as_slice().to_vec();
    ct.extend_from_slice(&ct_x);
    Ok((ct, combiner(ss_m.as_slice(), &ss_x, &ct_x, &pk_x)))
}

/// EncapsulateDerand from the draft (eseed = 32 bytes ML-KEM randomness || 32 bytes x25519 secret).
/// Needs feature `xwing-derand`. For tests only: fixed randomness breaks the KEM.
#[cfg(feature = "xwing-derand")]
pub fn encapsulate_derand(pk: &[u8], eseed: &[u8; 64]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), HybridError> {
    let (ek, pk_x) = parse_pk(pk)?;
    let m = ml_kem::B32::try_from(&eseed[..32]).expect("32 bytes");
    let (ct_m, ss_m) = ek.encapsulate_deterministic(&m);
    let esk: [u8; 32] = eseed[32..].try_into().unwrap();
    let ct_x = x25519_pub(&esk);
    let ss_x = Zeroizing::new(x25519_dalek::x25519(esk, pk_x));
    let mut ct = ct_m.as_slice().to_vec();
    ct.extend_from_slice(&ct_x);
    Ok((ct, combiner(ss_m.as_slice(), &ss_x, &ct_x, &pk_x)))
}

/// Seal a message to a hybrid public key with an Obsidian envelope `mode`
/// (0 = R1 research mode, 1 = XChaCha20-Poly1305, 2 = AES-256-GCM).
/// Output: X-Wing ciphertext (1120 bytes) || Obsidian envelope.
/// The key is fresh per message, so the random nonce cannot collide with an earlier key.
pub fn seal_to(pk: &[u8], mode: u8, plain: &[u8]) -> Result<Vec<u8>, HybridError> {
    let (mut out, key) = encapsulate(pk)?;
    let nonce: Zeroizing<[u8; 24]> = rand()?;
    let n = if mode == 2 { 12 } else { 24 };
    let env = seal(mode, &*key, &nonce[..n], plain).map_err(HybridError::Envelope)?;
    out.extend_from_slice(&env);
    Ok(out)
}

pub fn open_from(sk: &KemSecret, msg: &[u8]) -> Result<Vec<u8>, HybridError> {
    if msg.len() < KEM_CT_TOTAL {
        return Err(HybridError::InvalidCiphertext);
    }
    let key = sk.decapsulate(&msg[..KEM_CT_TOTAL])?;
    open(&*key, &msg[KEM_CT_TOTAL..]).map_err(HybridError::Envelope)
}

/// Long-term hybrid signing key: Ed25519 seed + ML-DSA-65 seed.
pub struct Signer {
    ed: EdSigningKey,
    dsa: DsaSigningKey<MlDsa65>,
}

fn ed_msg(msg: &[u8]) -> Vec<u8> {
    let mut m = SIG_CTX.to_vec();
    m.push(0);
    m.extend_from_slice(msg);
    m
}

impl Signer {
    pub fn generate() -> Result<Self, HybridError> {
        let e = rand::<32>()?;
        let d = rand::<32>()?;
        Ok(Self {
            ed: EdSigningKey::from_bytes(&e),
            dsa: DsaSigningKey::<MlDsa65>::from_seed(&ml_dsa::Seed::try_from(&d[..]).expect("32 bytes")),
        })
    }
    pub fn verifying_key(&self) -> Vec<u8> {
        let mut v = self.ed.verifying_key().to_bytes().to_vec();
        v.extend_from_slice(&ml_dsa::Keypair::verifying_key(&self.dsa).encode());
        v
    }
    /// Signature = Ed25519(64) || ML-DSA-65(3309), both over the same domain-separated message.
    /// ML-DSA is signed in deterministic mode, which FIPS 204 permits.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, HybridError> {
        let mut sig = self.ed.sign(&ed_msg(msg)).to_bytes().to_vec();
        let d = self
            .dsa
            .expanded_key()
            .sign_deterministic(msg, SIG_CTX)
            .map_err(|_| HybridError::InvalidSignature)?;
        sig.extend_from_slice(&d.encode());
        Ok(sig)
    }
}

/// Both signatures must verify. Either one failing rejects the message.
pub fn verify(vk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), HybridError> {
    if vk.len() != VK_LEN || sig.len() != SIG_LEN {
        return Err(HybridError::InvalidSignature);
    }
    let ed_vk = EdVerifyingKey::from_bytes(vk[..32].try_into().unwrap()).map_err(|_| HybridError::InvalidKey)?;
    let ed_sig = ed25519_dalek::Signature::from_bytes(sig[..ED_SIG_LEN].try_into().unwrap());
    let ed_ok = ed_vk.verify_strict(&ed_msg(msg), &ed_sig).is_ok();
    let dsa_vk = DsaVerifyingKey::<MlDsa65>::decode(
        &ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(&vk[32..]).map_err(|_| HybridError::InvalidKey)?,
    );
    let dsa_sig = ml_dsa::Signature::<MlDsa65>::decode(
        &ml_dsa::EncodedSignature::<MlDsa65>::try_from(&sig[ED_SIG_LEN..]).map_err(|_| HybridError::InvalidSignature)?,
    )
    .ok_or(HybridError::InvalidSignature)?;
    let dsa_ok = dsa_vk.verify_with_context(msg, SIG_CTX, &dsa_sig);
    if ed_ok & dsa_ok {
        Ok(())
    } else {
        Err(HybridError::InvalidSignature)
    }
}
