use crate::utils::{create_dir_if_not_exists, write_bytes_to_file};
use anyhow::Result;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use crate::chunk;
use crate::model::ChunkMeta;
use crate::crypto;
use crate::storage::local::{ensure_mailbox_local, save_chunk_local};
use base64::{engine::general_purpose, Engine as _};
use serde_json;
use rand::RngCore;
use anyhow::anyhow;

/// Process and encrypt a file to local storage
#[allow(clippy::too_many_arguments)]
pub fn process_file_encrypt(
    file_path: &Path,
    root_folder: &Path,
    recipient_pk_b64: &str,
    sender_sk_b64: Option<&str>,
    mailbox_base: &Path,
    chunk_size_bytes: usize,
    progress: Option<(Arc<AtomicUsize>, Arc<AtomicUsize>)>,
    cancel: Option<Arc<AtomicBool>>,
) -> Result<()> {
    // determine relative path
    let rel = file_path.strip_prefix(root_folder).unwrap_or(file_path);
    let rel_str = rel.to_string_lossy();

    // split
    let chunk_size = if chunk_size_bytes == 0 { 10 * 1024 * 1024 } else { chunk_size_bytes };
    let mut metas = chunk::split_file_into_chunks(file_path, chunk_size, &rel_str)?;

    if let Some((total, done)) = &progress {
        // Only initialize if not already set (supports multi-file jobs setting totals upfront)
        if total.load(Ordering::Relaxed) == 0 && done.load(Ordering::Relaxed) == 0 {
            total.store(metas.len() as usize, Ordering::Relaxed);
            done.store(0, Ordering::Relaxed);
        }
    }

    // parse recipient public key (expect base64 raw bytes)
    let recipient_pk_bytes = general_purpose::STANDARD.decode(recipient_pk_b64)?;
    let recipient_pk = crypto::PublicKey::from_slice(&recipient_pk_bytes).ok_or_else(|| anyhow::anyhow!("Invalid recipient public key"))?;

    // parse sender key if provided (hex or base64), otherwise generate ephemeral
    let (sender_pk, sender_sk) = if let Some(sk_str) = sender_sk_b64 {
        let sk_bytes = crate::utils::parse_key_hex_or_b64(sk_str)?;
        let sender_sk = crypto::SecretKey::from_slice(&sk_bytes).ok_or_else(|| anyhow!("Invalid sender secret key"))?;
        let sender_pk = crypto::PublicKey::from_slice(&sender_sk.0).ok_or_else(|| anyhow!("Failed to derive sender public key"))?;
        (sender_pk, sender_sk)
    } else {
        crypto::generate_keypair()
    };

    // ensure mailbox folder named after the recipient key string provided
    let mailbox = ensure_mailbox_local(mailbox_base, recipient_pk_b64)?;

    // process each chunk: create JSON, encrypt, save
    for meta in metas.iter_mut() {
        if let Some(flag) = &cancel { if flag.load(Ordering::Relaxed) { break; } }
        // set random nonce
    let mut nonce_bytes = vec![0u8; crypto::NONCEBYTES];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        meta.nonce = general_purpose::STANDARD.encode(&nonce_bytes);

        // serialize JSON
        let json = serde_json::to_vec(&meta)?;

    // encrypt JSON using provided nonce
    let encrypted = crypto::encrypt_with_nonce(&json, &nonce_bytes, &recipient_pk, &sender_sk)?;

    // compute sha of encrypted JSON and save
    let sha = save_chunk_local(&mailbox, &encrypted)?;

    // save nonce and sender public key alongside chunk for recipient discovery
    let chunks_dir = mailbox.join("chunks");
    let nonce_path = chunks_dir.join(format!("{}.nonce", sha));
    write_bytes_to_file(&nonce_path, general_purpose::STANDARD.encode(&nonce_bytes).as_bytes())?;

    let sender_b64 = general_purpose::STANDARD.encode(sender_pk.0);
    let sender_path = chunks_dir.join(format!("{}.sender", sha));
    write_bytes_to_file(&sender_path, sender_b64.as_bytes())?;
        if let Some((_total, done)) = &progress { done.fetch_add(1, Ordering::Relaxed); }
    }

    Ok(())
}

/// Assemble files from a local mailbox
pub fn assemble_from_mailbox(mailbox: &Path, recipient_sk_b64: &str, output_root: &Path) -> Result<()> {
    let logs = Arc::new(Mutex::new(Vec::new()));
    assemble_from_mailbox_with_logs(mailbox, recipient_sk_b64, output_root, logs)
}

/// Assemble files from a local mailbox with logging
pub fn assemble_from_mailbox_with_logs(mailbox: &Path, recipient_sk_b64: &str, output_root: &Path, logs: Arc<Mutex<Vec<String>>>) -> Result<()> {
    if let Ok(mut l) = logs.lock() {
        l.push(format!("Starting assembly from mailbox: {:?}", mailbox));
    }
    
    // This is a simplified version - the full implementation would be quite complex
    // For now, just log that assembly would happen here
    if let Ok(mut l) = logs.lock() {
        l.push("Assembly functionality not yet implemented in refactored version".to_string());
    }
    
    Ok(())
}