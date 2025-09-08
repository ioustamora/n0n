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
use std::sync::{Arc, Mutex};
use ssh2::Session;
use std::net::TcpStream;
use std::io::{Read, Write};

pub fn process_file_encrypt(file_path: &Path, root_folder: &Path, recipient_pk_b64: &str, sender_sk_b64: Option<&str>, mailbox_base: &Path) -> Result<()> {
    // determine relative path
    let rel = file_path.strip_prefix(root_folder).unwrap_or(file_path);
    let rel_str = rel.to_string_lossy();

    // split
    let chunk_size = 10 * 1024 * 1024; // default 10MB
    let mut metas = chunk::split_file_into_chunks(file_path, chunk_size, &rel_str)?;

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

// SFTP helper primitives (blocking). These provide basic connect/upload/download
// functionality used by a remote mailbox backend. They intentionally keep the
// Session and TcpStream alive while the SFTP handle is in use.
fn sftp_connect(host: &str, username: &str, password: &str) -> Result<(ssh2::Sftp, Session, TcpStream)> {
    // host may include port (host:22) or just host
    let tcp = TcpStream::connect(host)?;
    let mut sess = Session::new().map_err(|e| anyhow!("failed to create ssh session: {:?}", e))?;
    sess.set_tcp_stream(tcp.try_clone()?);
    sess.handshake()?;
    sess.userauth_password(username, password)?;
    if !sess.authenticated() {
        return Err(anyhow!("SFTP authentication failed"));
    }
    let sftp = sess.sftp()?;
    Ok((sftp, sess, tcp))
}

fn ensure_remote_dir(sftp: &ssh2::Sftp, path: &str) -> Result<()> {
    // create each component if it doesn't exist
    let mut comp = std::path::PathBuf::new();
    for part in path.split('/') {
        if part.is_empty() { continue; }
        comp.push(part);
        let ppath = std::path::Path::new(&comp);
        match sftp.stat(ppath) {
            Ok(_) => continue,
            Err(_) => {
                // try to create
                let _ = sftp.mkdir(ppath, 0o755);
            }
        }
    }
    Ok(())
}

fn remote_chunk_exists(sftp: &ssh2::Sftp, remote_path: &str) -> bool {
    let p = std::path::Path::new(remote_path);
    sftp.stat(p).is_ok()
}

pub fn upload_chunk_sftp(host: &str, username: &str, password: &str, remote_base: &str, recipient: &str, sha: &str, data: &[u8], nonce_b64: &str, sender_b64: &str) -> Result<()> {
    // connect
    let (sftp, _sess, _tcp) = sftp_connect(host, username, password)?;
    // ensure base/recipient/chunks exists
    let chunks_dir = format!("{}/{}/chunks", remote_base.trim_end_matches('/'), recipient);
    ensure_remote_dir(&sftp, &chunks_dir)?;

    let remote_chunk_path = format!("{}/{}", chunks_dir, sha);
    let remote_chunk_path_p = std::path::Path::new(&remote_chunk_path);
    if remote_chunk_exists(&sftp, &remote_chunk_path) {
        // deduplicate
    } else {
        let mut remote_file = sftp.create(remote_chunk_path_p)?;
        remote_file.write_all(data)?;
    }

    // write nonce and sender files
    let nonce_path = format!("{}.nonce", remote_chunk_path);
    let sender_path = format!("{}.sender", remote_chunk_path);
    let nonce_path_p = std::path::Path::new(&nonce_path);
    let sender_path_p = std::path::Path::new(&sender_path);
    if !remote_chunk_exists(&sftp, &nonce_path) {
        let mut nf = sftp.create(nonce_path_p)?;
        nf.write_all(nonce_b64.as_bytes())?;
    }
    if !remote_chunk_exists(&sftp, &sender_path) {
        let mut sf = sftp.create(sender_path_p)?;
        sf.write_all(sender_b64.as_bytes())?;
    }

    Ok(())
}

pub fn download_remote_file(host: &str, username: &str, password: &str, remote_path: &str) -> Result<Vec<u8>> {
    let (sftp, _sess, _tcp) = sftp_connect(host, username, password)?;
    let mut remote = sftp.open(remote_path)?;
    let mut buf = Vec::new();
    remote.read_to_end(&mut buf)?;
    Ok(buf)
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

pub fn assemble_from_mailbox_with_logs(mailbox: &Path, recipient_sk_b64: &str, output_root: &Path, logs: Arc<Mutex<Vec<String>>>) -> Result<()> {
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

        let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("?").to_string();
        if let Ok(mut l) = logs.lock() { l.push(format!("Reading chunk {}", fname)); }

        let encrypted = std::fs::read(&path)?;
        let sha = fname.clone();

        // read nonce and sender files
        let nonce_path = chunks_dir.join(format!("{}.nonce", sha));
        let sender_path = chunks_dir.join(format!("{}.sender", sha));
        let nonce_b64 = std::fs::read_to_string(&nonce_path)?;
        let sender_b64 = std::fs::read_to_string(&sender_path)?;

        let sender_bytes = general_purpose::STANDARD.decode(sender_b64.trim())?;
        let sender_pk = crypto::PublicKey::from_slice(&sender_bytes).ok_or_else(|| anyhow!("Invalid sender public key"))?;

        if let Ok(mut l) = logs.lock() { l.push(format!("Decrypting chunk {}", fname)); }

        // decrypt
        let json = crypto::decrypt_chunk(&encrypted, nonce_b64.trim(), &sender_pk, &recipient_sk)?;
        let meta: ChunkMeta = serde_json::from_slice(&json)?;

        files.entry(meta.file_sha256.clone()).or_default().push(meta);
    }

    // assemble files
    for (_sha, mut metas) in files {
        metas.sort_by_key(|m| m.chunk_index);
        if let Ok(mut l) = logs.lock() { l.push(format!("Assembling file {} ({} chunks)", metas.first().map(|m| m.file_name.clone()).unwrap_or_default(), metas.len())); }
        let assembled = chunk::assemble_file_from_chunks(&metas)?;
        chunk::verify_file_integrity(&metas, &assembled)?;

        // write file preserving relative path
        if let Some(first) = metas.first() {
            let out_path = output_root.join(&first.file_name);
            if let Some(parent) = out_path.parent() { std::fs::create_dir_all(parent)?; }
            write_bytes_to_file(&out_path, &assembled)?;
            if let Ok(mut l) = logs.lock() { l.push(format!("Wrote {}", out_path.display())); }
        }
    }

    if let Ok(mut l) = logs.lock() { l.push("Assembly finished".to_string()); }
    Ok(())
}
