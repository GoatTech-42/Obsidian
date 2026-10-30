//! Obsidian research baseline. Not independently audited; do not use for secrets.
use aes_gcm::{Aes256Gcm, Nonce};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;
type H = Hmac<Sha256>;
pub const MAX: usize = 1024 * 1024;
const MAGIC: &[u8; 4] = b"OBS1";
#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidKey,
    InvalidNonce,
    InvalidEnvelope,
    TooLarge,
    Authentication,
}
fn nonce_len(mode: u8) -> Result<usize, Error> {
    match mode {
        0 | 1 => Ok(24),
        2 => Ok(12),
        _ => Err(Error::InvalidEnvelope),
    }
}
fn mac(key: &[u8], data: &[u8]) -> H {
    let mut m = <H as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(data);
    m
}
fn keys(key: &[u8], nonce: &[u8]) -> Zeroizing<[u8; 64]> {
    let mut out = Zeroizing::new([0; 64]);
    Hkdf::<Sha256>::new(Some(nonce), key)
        .expand(b"Obsidian/R1/stream+auth", &mut *out)
        .expect("fixed valid HKDF length");
    out
}
fn xor_stream(key: &[u8], nonce: &[u8], input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    for (i, block) in input.chunks(32).enumerate() {
        let mut m = mac(key, b"Obsidian/R1/block");
        m.update(nonce);
        m.update(&(i as u64).to_be_bytes());
        let stream = Zeroizing::new(<[u8; 32]>::from(m.finalize().into_bytes()));
        out.extend(block.iter().zip(stream.iter()).map(|(a, b)| a ^ b));
    }
    out
}
/// Nonces must be freshly random per message. This raw API cannot enforce uniqueness.
pub fn seal(mode: u8, key: &[u8], nonce: &[u8], plain: &[u8]) -> Result<Vec<u8>, Error> {
    if key.len() != 32 {
        return Err(Error::InvalidKey);
    }
    let n = nonce_len(mode)?;
    if nonce.len() != n {
        return Err(Error::InvalidNonce);
    }
    if plain.len() > MAX {
        return Err(Error::TooLarge);
    }
    let mut header = Vec::from(MAGIC.as_slice());
    header.push(mode);
    header.extend_from_slice(&[0, 0, 0]);
    header.extend_from_slice(nonce);
    let body = match mode {
        0 => {
            let k = keys(key, nonce);
            let mut b = xor_stream(&k[..32], nonce, plain);
            let mut m = mac(&k[32..], &header);
            m.update(&b);
            b.extend_from_slice(&m.finalize().into_bytes());
            b
        }
        1 => XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| Error::InvalidKey)?
            .encrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: plain,
                    aad: &header,
                },
            )
            .map_err(|_| Error::Authentication)?,
        2 => Aes256Gcm::new_from_slice(key)
            .map_err(|_| Error::InvalidKey)?
            .encrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: plain,
                    aad: &header,
                },
            )
            .map_err(|_| Error::Authentication)?,
        _ => unreachable!(),
    };
    header.extend(body);
    Ok(header)
}
pub fn open(key: &[u8], envelope: &[u8]) -> Result<Vec<u8>, Error> {
    if key.len() != 32 {
        return Err(Error::InvalidKey);
    }
    if envelope.len() < 8 || &envelope[..4] != MAGIC || envelope[5..8] != [0, 0, 0] {
        return Err(Error::InvalidEnvelope);
    }
    let mode = envelope[4];
    let n = nonce_len(mode)?;
    let tag = if mode == 0 { 32 } else { 16 };
    if envelope.len() < 8 + n + tag {
        return Err(Error::InvalidEnvelope);
    }
    if envelope.len() > 8 + n + tag + MAX {
        return Err(Error::TooLarge);
    }
    let header = &envelope[..8 + n];
    let nonce = &envelope[8..8 + n];
    let body = &envelope[8 + n..];
    match mode {
        0 => {
            let k = keys(key, nonce);
            let (cipher, tag) = body.split_at(body.len() - 32);
            let mut m = mac(&k[32..], header);
            m.update(cipher);
            m.verify_slice(tag).map_err(|_| Error::Authentication)?;
            Ok(xor_stream(&k[..32], nonce, cipher))
        }
        1 => XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| Error::InvalidKey)?
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: body,
                    aad: header,
                },
            )
            .map_err(|_| Error::Authentication),
        2 => Aes256Gcm::new_from_slice(key)
            .map_err(|_| Error::InvalidKey)?
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: body,
                    aad: header,
                },
            )
            .map_err(|_| Error::Authentication),
        _ => Err(Error::InvalidEnvelope),
    }
}
#[wasm_bindgen]
pub fn encrypt(mode: u8, key: Vec<u8>, nonce: Vec<u8>, plain: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    // Take ownership of the glue-passed copies so secret inputs are wiped
    // while owned, before their allocations are released: Zeroizing zeroes
    // the buffer on drop, before the Vec frees it, on success and error paths.
    let key = Zeroizing::new(key);
    let plain = Zeroizing::new(plain);
    seal(mode, &key, &nonce, &plain).map_err(|e| JsValue::from_str(&format!("{e:?}")))
}
#[wasm_bindgen]
pub fn decrypt(key: Vec<u8>, envelope: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    let key = Zeroizing::new(key);
    open(&key, &envelope).map_err(|e| JsValue::from_str(&format!("{e:?}")))
}
