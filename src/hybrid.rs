//! Hybrid classical + post-quantum key establishment and signatures for Obsidian.
//!
//! Built only from existing, standardized primitives through the RustCrypto crates
//! `ml-kem` (FIPS 203, ML-KEM-768), `ml-dsa` (FIPS 204, ML-DSA-65), `x25519-dalek` and
//! `ed25519-dalek`. Nothing here is a new primitive.
//!
//! The KEM is X25519 + ML-KEM-768 joined with HKDF-SHA256. It is in the style of X-Wing
//! and the IETF hybrid drafts, but it is NOT X-Wing and the combiner is not standardized.
//! An attacker has to break BOTH X25519 and ML-KEM-768 to learn the key. The signature is
//! Ed25519 + ML-DSA-65 and BOTH must verify.
//!
//! Not independently audited. The underlying crates state they are unaudited. Obsidian's
//! own cipher is not what makes this layer post-quantum: a 256-bit symmetric key is
//! already out of reach of known quantum attacks, the quantum-exposed parts are key
//! exchange and signatures, and those come from ML-KEM and ML-DSA here.
use crate::{open, seal, Error};
use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey};
use hkdf::Hkdf;
use ml_dsa::{MlDsa65, SigningKey as DsaSigningKey, VerifyingKey as DsaVerifyingKey};
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    Ciphertext, DecapsulationKey, EncapsulationKey, KeyExport, MlKem768, Seed as KemSeed,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const X_LEN: usize = 32;
pub const KEM_EK_LEN: usize = 1184;
pub const KEM_CT_LEN: usize = 1088;
pub const DSA_VK_LEN: usize = 1952;
pub const DSA_SIG_LEN: usize = 3309;
pub const ED_SIG_LEN: usize = 64;
/// Public key: x25519(32) || ml-kem-768 encapsulation key(1184).
pub const KEM_PK_LEN: usize = X_LEN + KEM_EK_LEN;
/// KEM ciphertext: ephemeral x25519(32) || ml-kem-768 ciphertext(1088).
pub const KEM_CT_TOTAL: usize = X_LEN + KEM_CT_LEN;
/// Signature: ed25519(64) || ml-dsa-65(3309).
pub const SIG_LEN: usize = ED_SIG_LEN + DSA_SIG_LEN;
/// Verifying key: ed25519(32) || ml-dsa-65(1952).
pub const VK_LEN: usize = 32 + DSA_VK_LEN;

const KEM_LABEL: &[u8] = b"Obsidian/hybrid-kem/v1/x25519+mlkem768";
const SIG_CTX: &[u8] = b"Obsidian/hybrid-sig/v1";

#[derive(Debug, PartialEq)]
pub enum HybridError {
    Random,
    InvalidKey,
    InvalidCiphertext,
    /// X25519 produced the all-zero output (low-order point).
    WeakPoint,
    InvalidSignature,
    Envelope(Error),
}

fn rand<const N: usize>() -> Result<Zeroizing<[u8; N]>, HybridError> {
    let mut b = Zeroizing::new([0u8; N]);
    getrandom4::fill(&mut *b).map_err(|_| HybridError::Random)?;
    Ok(b)
}

fn combine(ss_pq: &[u8], ss_x: &[u8; 32], eph: &[u8; 32], rcpt: &[u8; 32], ek: &[u8], ct: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(ss_pq);
    ikm.extend_from_slice(ss_x);
    let mut info = Vec::new();
    info.extend_from_slice(eph);
    info.extend_from_slice(rcpt);
    info.extend_from_slice(&Sha256::digest(ek));
    info.extend_from_slice(ct);
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(KEM_LABEL), &ikm)
        .expand(&info, &mut *out)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    out
}

/// Long-term hybrid KEM secret: an x25519 secret and a 64-byte ML-KEM seed.
pub struct KemSecret {
    x: Zeroizing<[u8; 32]>,
    seed: Zeroizing<[u8; 64]>,
}

impl KemSecret {
    pub fn generate() -> Result<Self, HybridError> {
        Ok(Self { x: rand::<32>()?, seed: rand::<64>()? })
    }
    fn dk(&self) -> DecapsulationKey<MlKem768> {
        DecapsulationKey::<MlKem768>::from_seed(KemSeed::try_from(&self.seed[..]).expect("64 bytes"))
    }
    pub fn public_key(&self) -> Vec<u8> {
        let xp = x25519_dalek::x25519(*self.x, x25519_dalek::X25519_BASEPOINT_BYTES);
        let mut pk = xp.to_vec();
        pk.extend_from_slice(&self.dk().encapsulation_key().to_bytes());
        pk
    }
    /// Recover the 32-byte shared key from a hybrid KEM ciphertext.
    pub fn decapsulate(&self, ct: &[u8]) -> Result<Zeroizing<[u8; 32]>, HybridError> {
        if ct.len() != KEM_CT_TOTAL {
            return Err(HybridError::InvalidCiphertext);
        }
        let eph: [u8; 32] = ct[..32].try_into().unwrap();
        let ct_pq = &ct[32..];
        let ss_x = Zeroizing::new(x25519_dalek::x25519(*self.x, eph));
        if ss_x.iter().all(|b| *b == 0) {
            return Err(HybridError::WeakPoint);
        }
        let dk = self.dk();
        let c = Ciphertext::<MlKem768>::try_from(ct_pq).map_err(|_| HybridError::InvalidCiphertext)?;
        let ss_pq = dk.decapsulate(&c);
        let rcpt = x25519_dalek::x25519(*self.x, x25519_dalek::X25519_BASEPOINT_BYTES);
        let ek = dk.encapsulation_key().to_bytes();
        Ok(combine(ss_pq.as_slice(), &ss_x, &eph, &rcpt, &ek, ct_pq))
    }
}

/// Encapsulate to a public key. Returns (ciphertext to send, 32-byte shared key).
pub fn encapsulate(pk: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), HybridError> {
    if pk.len() != KEM_PK_LEN {
        return Err(HybridError::InvalidKey);
    }
    let rcpt: [u8; 32] = pk[..32].try_into().unwrap();
    let ek_bytes = &pk[32..];
    let key = ml_kem::Key::<EncapsulationKey<MlKem768>>::try_from(ek_bytes).map_err(|_| HybridError::InvalidKey)?;
    let ek = EncapsulationKey::<MlKem768>::new(&key).map_err(|_| HybridError::InvalidKey)?;
    let (ct_pq, ss_pq) = ek.encapsulate();
    let esk = rand::<32>()?;
    let eph = x25519_dalek::x25519(*esk, x25519_dalek::X25519_BASEPOINT_BYTES);
    let ss_x = Zeroizing::new(x25519_dalek::x25519(*esk, rcpt));
    if ss_x.iter().all(|b| *b == 0) {
        return Err(HybridError::WeakPoint);
    }
    let mut ct = eph.to_vec();
    ct.extend_from_slice(ct_pq.as_slice());
    let k = combine(ss_pq.as_slice(), &ss_x, &eph, &rcpt, ek_bytes, ct_pq.as_slice());
    Ok((ct, k))
}

/// Seal a message to a hybrid public key with an Obsidian envelope `mode`
/// (0 = R1 research mode, 1 = XChaCha20-Poly1305, 2 = AES-256-GCM).
/// Output: hybrid KEM ciphertext (1120 bytes) || Obsidian envelope.
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
