use crate::model::StorageBackend;
use crate::utils::{create_dir_if_not_exists, compute_sha256, write_bytes_to_file};
use anyhow::Result;
use std::path::{Path, PathBuf};
use std::fs;
use crate::chunk;
use crate::model::ChunkMeta;
use crate::crypto;
use base64::{engine::general_purpose, Engine as _};
use serde_json;
use rand::RngCore;
use anyhow::anyhow;
use std::collections::HashMap;

pub fn process_file_encrypt(file_path: &Path, root_folder: &Path, recipient_pk_b64: &str, _sender_sk_b64: Option<&str>, mailbox_base: &Path) -> Result<()> {
    // determine relative path
    let rel = file_path.strip_prefix(root_folder).unwrap_or(file_path);
    let rel_str = rel.to_string_lossy();

    // split
    let chunk_size = 10 * 1024 * 1024; // default 10MB
    let mut metas = chunk::split_file_into_chunks(file_path, chunk_size, &rel_str)?;

    // parse recipient public key (expect base64 raw bytes)
    let recipient_pk_bytes = general_purpose::STANDARD.decode(recipient_pk_b64)?;
    let recipient_pk = crypto::PublicKey::from_slice(&recipient_pk_bytes).ok_or_else(|| anyhow::anyhow!("Invalid recipient public key"))?;

    // generate sender keypair (ephemeral)
    let (sender_pk, sender_sk) = crypto::generate_keypair();

    // ensure mailbox folder named after the recipient key string provided
    let mailbox = ensure_mailbox_local(mailbox_base, recipient_pk_b64)?;

    // process each chunk: create JSON, encrypt, save
    for meta in metas.iter_mut() {
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

    let sender_b64 = general_purpose::STANDARD.encode(&sender_pk.0);
    let sender_path = chunks_dir.join(format!("{}.sender", sha));
    write_bytes_to_file(&sender_path, sender_b64.as_bytes())?;
    }

    Ok(())
}

pub fn ensure_mailbox_local(base: &Path, recipient: &str) -> Result<PathBuf> {
    let mailbox = base.join(recipient);
    create_dir_if_not_exists(&mailbox)?;
    Ok(mailbox)
}

pub fn save_chunk_local(mailbox: &Path, encrypted: &[u8]) -> Result<String> {
    // filename is sha256 of encrypted data
    let hash = compute_sha256(encrypted);
    let chunks_dir = mailbox.join("chunks");
    create_dir_if_not_exists(&chunks_dir)?;
    let path = chunks_dir.join(&hash);
    if path.exists() {
        // deduplicate
        return Ok(hash);
    }
    write_bytes_to_file(&path, encrypted)?;
    Ok(hash)
}

// SFTP and cloud backends are left as placeholders for now.
pub async fn ensure_mailbox_sftp(_host: &str, _user: &str, _password: &str, _path: &str, _recipient: &str) -> Result<()> {
    // TODO: implement SFTP mailbox creation
    Ok(())
}

pub fn assemble_from_mailbox(mailbox: &Path, recipient_sk_b64: &str, output_root: &Path) -> Result<()> {
    let chunks_dir = mailbox.join("chunks");
    if !chunks_dir.exists() { return Err(anyhow!("chunks directory missing")); }

    // parse recipient secret key
    let sk_bytes = general_purpose::STANDARD.decode(recipient_sk_b64)?;
    let recipient_sk = crypto::SecretKey::from_slice(&sk_bytes).ok_or_else(|| anyhow!("Invalid recipient secret key"))?;

    // map file_sha -> Vec<ChunkMeta>
    let mut files: HashMap<String, Vec<ChunkMeta>> = HashMap::new();

    for entry in std::fs::read_dir(&chunks_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("sender") { continue; }
        if path.extension().and_then(|s| s.to_str()) == Some("nonce") { continue; }

        let encrypted = std::fs::read(&path)?;
        let sha = path.file_name().and_then(|s| s.to_str()).ok_or_else(|| anyhow!("Invalid filename"))?.to_string();

        // read nonce and sender files
        let nonce_path = chunks_dir.join(format!("{}.nonce", sha));
        let sender_path = chunks_dir.join(format!("{}.sender", sha));
        let nonce_b64 = std::fs::read_to_string(&nonce_path)?;
        let sender_b64 = std::fs::read_to_string(&sender_path)?;

        let sender_bytes = general_purpose::STANDARD.decode(sender_b64.trim())?;
        let sender_pk = crypto::PublicKey::from_slice(&sender_bytes).ok_or_else(|| anyhow!("Invalid sender public key"))?;

        // decrypt
        let json = crypto::decrypt_chunk(&encrypted, nonce_b64.trim(), &sender_pk, &recipient_sk)?;
        let meta: ChunkMeta = serde_json::from_slice(&json)?;

        // verify chunk sha matches plaintext chunk data
        files.entry(meta.file_sha256.clone()).or_default().push(meta);
    }

    // assemble files
    for (_sha, mut metas) in files {
        metas.sort_by_key(|m| m.chunk_index);
        let assembled = chunk::assemble_file_from_chunks(&metas)?;
        chunk::verify_file_integrity(&metas, &assembled)?;

        // write file preserving relative path
        if let Some(first) = metas.first() {
            let out_path = output_root.join(&first.file_name);
            if let Some(parent) = out_path.parent() { std::fs::create_dir_all(parent)?; }
            write_bytes_to_file(&out_path, &assembled)?;
        }
    }

    Ok(())
}
