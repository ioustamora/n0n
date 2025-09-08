use sodiumoxide::crypto::box_;
pub use sodiumoxide::crypto::box_::{PublicKey, SecretKey, PrecomputedKey};
pub use sodiumoxide::crypto::box_::NONCEBYTES;
use crate::utils::{encode_base64, decode_base64};
use anyhow::{Result, anyhow};

pub fn init() {
	let _ = sodiumoxide::init();
}

pub fn generate_keypair() -> (PublicKey, SecretKey) {
	box_::gen_keypair()
}

#[allow(dead_code)]
pub fn encrypt_chunk(plaintext: &[u8], recipient_pk: &PublicKey, sender_sk: &SecretKey) -> Result<(Vec<u8>, String)> {
	let nonce = box_::gen_nonce();
	let ciphertext = box_::seal(plaintext, &nonce, recipient_pk, sender_sk);
	Ok((ciphertext, encode_base64(&nonce.0)))
}

pub fn decrypt_chunk(ciphertext: &[u8], nonce_b64: &str, sender_pk: &PublicKey, recipient_sk: &SecretKey) -> Result<Vec<u8>> {
	let nonce_bytes = decode_base64(nonce_b64)?;
	if nonce_bytes.len() != NONCEBYTES { return Err(anyhow!("Invalid nonce length")); }
	let mut nonce_arr = [0u8; NONCEBYTES];
	nonce_arr.copy_from_slice(&nonce_bytes);
	let nonce = box_::Nonce(nonce_arr);
	box_::open(ciphertext, &nonce, sender_pk, recipient_sk).map_err(|_| anyhow!("Decryption failed"))
}

#[allow(dead_code)]
pub fn precompute_shared(sender_sk: &SecretKey, recipient_pk: &PublicKey) -> PrecomputedKey {
	box_::precompute(recipient_pk, sender_sk)
}

pub fn encrypt_with_nonce(plaintext: &[u8], nonce_bytes: &[u8], recipient_pk: &PublicKey, sender_sk: &SecretKey) -> Result<Vec<u8>> {
	if nonce_bytes.len() != NONCEBYTES { return Err(anyhow!("Invalid nonce length")); }
	let mut nonce_arr = [0u8; NONCEBYTES];
	nonce_arr.copy_from_slice(nonce_bytes);
	let nonce = box_::Nonce(nonce_arr);
	Ok(box_::seal(plaintext, &nonce, recipient_pk, sender_sk))
}
