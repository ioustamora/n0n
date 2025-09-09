use crate::utils::{create_dir_if_not_exists, compute_sha256, write_bytes_to_file};
use anyhow::Result;
use std::path::{Path, PathBuf};
use crate::chunk;
use crate::model::ChunkMeta;
use crate::crypto;
use base64::{engine::general_purpose, Engine as _};
use serde_json;
use rand::RngCore;
use anyhow::anyhow;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use ssh2::Session;
use std::net::TcpStream;
use std::io::{Read, Write};

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
#[allow(dead_code)]
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

// Flexible SSH auth and host key verification
pub enum SshAuth<'a> {
    Password(&'a str),
    Key { private_key: &'a str, passphrase: Option<&'a str> },
}

fn sftp_connect_with(host: &str, username: &str, auth: SshAuth, expected_host_fp_sha256_b64: Option<&str>) -> Result<(ssh2::Sftp, Session, TcpStream)> {
    let tcp = TcpStream::connect(host)?;
    let mut sess = Session::new().map_err(|e| anyhow!("failed to create ssh session: {:?}", e))?;
    sess.set_tcp_stream(tcp.try_clone()?);
    sess.handshake()?;

    // Host key verification (SHA-256 over raw host key bytes, base64-encoded)
    if let Some(expected_b64) = expected_host_fp_sha256_b64 {
        if let Some((hostkey, _typ)) = sess.host_key() {
            use sha2::{Digest, Sha256};
            let fp = Sha256::digest(hostkey);
            let got_b64 = base64::engine::general_purpose::STANDARD.encode(fp);
            // Allow optional padding differences by trimming '=' on both sides
            let exp_trim = expected_b64.trim_end_matches('=');
            let got_trim = got_b64.trim_end_matches('=');
            if exp_trim != got_trim {
                return Err(anyhow!("Host key fingerprint mismatch"));
            }
        } else {
            return Err(anyhow!("Unable to obtain SSH host key"));
        }
    }

    match auth {
        SshAuth::Password(pw) => sess.userauth_password(username, pw)?,
        SshAuth::Key { private_key, passphrase } => {
            let pk_path = std::path::Path::new(private_key);
            sess.userauth_pubkey_file(username, None, pk_path, passphrase)?;
        }
    }

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

#[allow(clippy::too_many_arguments)]
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
        // atomic upload: write to temp then rename
        let tmp_path = format!("{}.tmp", remote_chunk_path);
        let mut attempts = 0;
        loop {
            attempts += 1;
            let res: Result<()> = (|| {
                let mut tmpf = sftp.create(std::path::Path::new(&tmp_path))?;
                tmpf.write_all(data)?;
                sftp.rename(std::path::Path::new(&tmp_path), remote_chunk_path_p, None)?;
                Ok(())
            })();
            match res {
                Ok(()) => break,
                Err(_e) if attempts < 3 => {
                    std::thread::sleep(std::time::Duration::from_millis(200 * attempts));
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }

    // write nonce and sender files
    let nonce_path = format!("{}.nonce", remote_chunk_path);
    let sender_path = format!("{}.sender", remote_chunk_path);
    let nonce_path_p = std::path::Path::new(&nonce_path);
    let sender_path_p = std::path::Path::new(&sender_path);
    if !remote_chunk_exists(&sftp, &nonce_path) {
        let tmp = format!("{}.tmp", nonce_path);
        let mut nf = sftp.create(std::path::Path::new(&tmp))?;
        nf.write_all(nonce_b64.as_bytes())?;
        let _ = sftp.rename(std::path::Path::new(&tmp), nonce_path_p, None);
    }
    if !remote_chunk_exists(&sftp, &sender_path) {
        let tmp = format!("{}.tmp", sender_path);
        let mut sf = sftp.create(std::path::Path::new(&tmp))?;
        sf.write_all(sender_b64.as_bytes())?;
        let _ = sftp.rename(std::path::Path::new(&tmp), sender_path_p, None);
    }

    Ok(())
}

/// Test SFTP connectivity with password auth and basic access to the base directory.
pub fn test_sftp_connection(host: &str, username: &str, password: &str, remote_base: &str) -> Result<()> {
    let (sftp, _sess, _tcp) = sftp_connect(host, username, password)?;
    // Check that base exists and is accessible
    let base_path = std::path::Path::new(remote_base.trim_end_matches('/'));
    let _ = sftp.stat(base_path)?;
    Ok(())
}

/// Test SFTP connectivity with flexible auth and optional host fingerprint verification.
pub fn test_sftp_connection_auth(
    host: &str,
    username: &str,
    password: Option<&str>,
    private_key: Option<&str>,
    private_key_pass: Option<&str>,
    expected_host_fp_sha256_b64: Option<&str>,
    remote_base: &str,
) -> Result<()> {
    let auth = if let Some(pk) = private_key {
        SshAuth::Key { private_key: pk, passphrase: private_key_pass }
    } else if let Some(pw) = password {
        SshAuth::Password(pw)
    } else {
        return Err(anyhow!("No SFTP auth provided"));
    };
    let (sftp, _sess, _tcp) = sftp_connect_with(host, username, auth, expected_host_fp_sha256_b64)?;
    let base_path = std::path::Path::new(remote_base.trim_end_matches('/'));
    let _ = sftp.stat(base_path)?;
    Ok(())
}

// Auth-aware variant supporting SSH keys and host key verification
#[allow(clippy::too_many_arguments)]
pub fn upload_chunk_sftp_auth(
    host: &str,
    username: &str,
    password: Option<&str>,
    private_key: Option<&str>,
    private_key_pass: Option<&str>,
    expected_host_fp_sha256_b64: Option<&str>,
    remote_base: &str,
    recipient: &str,
    sha: &str,
    data: &[u8],
    nonce_b64: &str,
    sender_b64: &str,
) -> Result<()> {
    let auth = match (private_key, password) {
        (Some(pk), _) => SshAuth::Key { private_key: pk, passphrase: private_key_pass },
        (None, Some(pw)) => SshAuth::Password(pw),
        _ => return Err(anyhow!("No SSH auth provided")),
    };
    let (sftp, _sess, _tcp) = sftp_connect_with(host, username, auth, expected_host_fp_sha256_b64)?;

    // ensure base/recipient/chunks exists
    let chunks_dir = format!("{}/{}/chunks", remote_base.trim_end_matches('/'), recipient);
    ensure_remote_dir(&sftp, &chunks_dir)?;

    let remote_chunk_path = format!("{}/{}", chunks_dir, sha);
    let remote_chunk_path_p = std::path::Path::new(&remote_chunk_path);
    if remote_chunk_exists(&sftp, &remote_chunk_path) {
        // deduplicate
    } else {
        // atomic upload: write to temp then rename
        let tmp_path = format!("{}.tmp", remote_chunk_path);
        let mut attempts = 0;
        loop {
            attempts += 1;
            let res: Result<()> = (|| {
                let mut tmpf = sftp.create(std::path::Path::new(&tmp_path))?;
                tmpf.write_all(data)?;
                sftp.rename(std::path::Path::new(&tmp_path), remote_chunk_path_p, None)?;
                Ok(())
            })();
            match res {
                Ok(()) => break,
                Err(_e) if attempts < 3 => {
                    std::thread::sleep(std::time::Duration::from_millis(200 * attempts));
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }

    // write nonce and sender files
    let nonce_path = format!("{}.nonce", remote_chunk_path);
    let sender_path = format!("{}.sender", remote_chunk_path);
    let nonce_path_p = std::path::Path::new(&nonce_path);
    let sender_path_p = std::path::Path::new(&sender_path);
    if !remote_chunk_exists(&sftp, &nonce_path) {
        let tmp = format!("{}.tmp", nonce_path);
        let mut nf = sftp.create(std::path::Path::new(&tmp))?;
        nf.write_all(nonce_b64.as_bytes())?;
        let _ = sftp.rename(std::path::Path::new(&tmp), nonce_path_p, None);
    }
    if !remote_chunk_exists(&sftp, &sender_path) {
        let tmp = format!("{}.tmp", sender_path);
        let mut sf = sftp.create(std::path::Path::new(&tmp))?;
        sf.write_all(sender_b64.as_bytes())?;
        let _ = sftp.rename(std::path::Path::new(&tmp), sender_path_p, None);
    }

    Ok(())
}

#[allow(dead_code)]
pub fn download_remote_file(host: &str, username: &str, password: &str, remote_path: &str) -> Result<Vec<u8>> {
    let (sftp, _sess, _tcp) = sftp_connect(host, username, password)?;
    let mut remote = sftp.open(remote_path)?;
    let mut buf = Vec::new();
    remote.read_to_end(&mut buf)?;
    Ok(buf)
}

#[allow(dead_code)]
pub fn download_remote_file_auth(host: &str, username: &str, password: Option<&str>, private_key: Option<&str>, private_key_pass: Option<&str>, expected_host_fp_sha256_b64: Option<&str>, remote_path: &str) -> Result<Vec<u8>> {
    let auth = match (private_key, password) {
        (Some(pk), _) => SshAuth::Key { private_key: pk, passphrase: private_key_pass },
        (None, Some(pw)) => SshAuth::Password(pw),
        _ => return Err(anyhow!("No SSH auth provided")),
    };
    let (sftp, _sess, _tcp) = sftp_connect_with(host, username, auth, expected_host_fp_sha256_b64)?;
    let mut remote = sftp.open(std::path::Path::new(remote_path))?;
    let mut buf = Vec::new();
    remote.read_to_end(&mut buf)?;
    Ok(buf)
}

// Encrypt a file and upload its chunks to SFTP mailbox
#[allow(clippy::too_many_arguments)]
pub fn process_file_encrypt_to_sftp(
    file_path: &Path,
    root_folder: &Path,
    recipient_pk_b64: &str,
    recipient_folder_id: &str,
    sender_sk_b64: Option<&str>,
    host: &str,
    username: &str,
    password: &str,
    remote_base: &str,
    chunk_size_bytes: usize,
    progress: Option<(Arc<AtomicUsize>, Arc<AtomicUsize>)>,
    cancel: Option<Arc<AtomicBool>>,
) -> Result<()> {
    // determine relative path
    let rel = file_path.strip_prefix(root_folder).unwrap_or(file_path);
    let rel_str = rel.to_string_lossy();

    // split with default 10MB chunks for now
    let chunk_size = if chunk_size_bytes == 0 { 10 * 1024 * 1024 } else { chunk_size_bytes };
    let mut metas = chunk::split_file_into_chunks(file_path, chunk_size, &rel_str)?;

    if let Some((total, done)) = &progress {
        if total.load(Ordering::Relaxed) == 0 && done.load(Ordering::Relaxed) == 0 {
            total.store(metas.len() as usize, Ordering::Relaxed);
            done.store(0, Ordering::Relaxed);
        }
    }

    // parse recipient public key
    let recipient_pk_bytes = general_purpose::STANDARD.decode(recipient_pk_b64)?;
    let recipient_pk = crypto::PublicKey::from_slice(&recipient_pk_bytes)
        .ok_or_else(|| anyhow!("Invalid recipient public key"))?;

    // sender key or ephemeral
    let (sender_pk, sender_sk) = if let Some(sk_str) = sender_sk_b64 {
        let sk_bytes = crate::utils::parse_key_hex_or_b64(sk_str)?;
        let sender_sk = crypto::SecretKey::from_slice(&sk_bytes)
            .ok_or_else(|| anyhow!("Invalid sender secret key"))?;
        let sender_pk = crypto::PublicKey::from_slice(&sender_sk.0)
            .ok_or_else(|| anyhow!("Failed to derive sender public key"))?;
        (sender_pk, sender_sk)
    } else {
        crypto::generate_keypair()
    };

    for meta in metas.iter_mut() {
        if let Some(flag) = &cancel { if flag.load(Ordering::Relaxed) { break; } }
        // set random nonce
        let mut nonce_bytes = vec![0u8; crypto::NONCEBYTES];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        meta.nonce = general_purpose::STANDARD.encode(&nonce_bytes);

        // serialize and encrypt
        let json = serde_json::to_vec(&meta)?;
        let encrypted = crypto::encrypt_with_nonce(&json, &nonce_bytes, &recipient_pk, &sender_sk)?;

        // compute sha filename
        let sha = compute_sha256(&encrypted);

        // upload
        let sender_b64 = general_purpose::STANDARD.encode(sender_pk.0);
        let nonce_b64 = general_purpose::STANDARD.encode(&nonce_bytes);
    upload_chunk_sftp(
            host,
            username,
            password,
            remote_base,
            recipient_folder_id,
            &sha,
            &encrypted,
            &nonce_b64,
            &sender_b64,
        )?;

    if let Some((_total, done)) = &progress { done.fetch_add(1, Ordering::Relaxed); }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn process_file_encrypt_to_sftp_auth(
    file_path: &Path,
    root_folder: &Path,
    recipient_pk_b64: &str,
    recipient_folder_id: &str,
    sender_sk_b64: Option<&str>,
    host: &str,
    username: &str,
    password: Option<&str>,
    private_key: Option<&str>,
    private_key_pass: Option<&str>,
    expected_host_fp_sha256_b64: Option<&str>,
    remote_base: &str,
    chunk_size_bytes: usize,
    progress: Option<(Arc<AtomicUsize>, Arc<AtomicUsize>)>,
    cancel: Option<Arc<AtomicBool>>,
) -> Result<()> {
    // determine relative path
    let rel = file_path.strip_prefix(root_folder).unwrap_or(file_path);
    let rel_str = rel.to_string_lossy();

    let chunk_size = if chunk_size_bytes == 0 { 10 * 1024 * 1024 } else { chunk_size_bytes };
    let mut metas = chunk::split_file_into_chunks(file_path, chunk_size, &rel_str)?;

    if let Some((total, done)) = &progress {
        if total.load(Ordering::Relaxed) == 0 && done.load(Ordering::Relaxed) == 0 {
            total.store(metas.len() as usize, Ordering::Relaxed);
            done.store(0, Ordering::Relaxed);
        }
    }

    let recipient_pk_bytes = general_purpose::STANDARD.decode(recipient_pk_b64)?;
    let recipient_pk = crypto::PublicKey::from_slice(&recipient_pk_bytes)
        .ok_or_else(|| anyhow!("Invalid recipient public key"))?;

    let (sender_pk, sender_sk) = if let Some(sk_str) = sender_sk_b64 {
        let sk_bytes = crate::utils::parse_key_hex_or_b64(sk_str)?;
        let sender_sk = crypto::SecretKey::from_slice(&sk_bytes)
            .ok_or_else(|| anyhow!("Invalid sender secret key"))?;
        let sender_pk = crypto::PublicKey::from_slice(&sender_sk.0)
            .ok_or_else(|| anyhow!("Failed to derive sender public key"))?;
        (sender_pk, sender_sk)
    } else {
        crypto::generate_keypair()
    };

    for meta in metas.iter_mut() {
        if let Some(flag) = &cancel { if flag.load(Ordering::Relaxed) { break; } }
        let mut nonce_bytes = vec![0u8; crypto::NONCEBYTES];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        meta.nonce = general_purpose::STANDARD.encode(&nonce_bytes);

        let json = serde_json::to_vec(&meta)?;
        let encrypted = crypto::encrypt_with_nonce(&json, &nonce_bytes, &recipient_pk, &sender_sk)?;

        let sha = compute_sha256(&encrypted);
        let sender_b64 = general_purpose::STANDARD.encode(sender_pk.0);
        let nonce_b64 = general_purpose::STANDARD.encode(&nonce_bytes);
    upload_chunk_sftp_auth(
            host,
            username,
            password,
            private_key,
            private_key_pass,
            expected_host_fp_sha256_b64,
            remote_base,
            recipient_folder_id,
            &sha,
            &encrypted,
            &nonce_b64,
            &sender_b64,
        )?;

    if let Some((_total, done)) = &progress { done.fetch_add(1, Ordering::Relaxed); }
    }

    Ok(())
}

// Assemble from SFTP mailbox with logs
#[allow(clippy::too_many_arguments)]
pub fn assemble_from_sftp_with_logs(
    host: &str,
    username: &str,
    password: &str,
    remote_base: &str,
    recipient_id: &str,
    recipient_sk_b64: &str,
    output_root: &Path,
    logs: Arc<Mutex<Vec<String>>>
) -> Result<()> {
    // connect and open chunks dir
    let (sftp, _sess, _tcp) = sftp_connect(host, username, password)?;
    let chunks_dir = format!("{}/{}/chunks", remote_base.trim_end_matches('/'), recipient_id);

    // parse recipient secret key
    let sk_bytes = general_purpose::STANDARD.decode(recipient_sk_b64)?;
    let recipient_sk = crypto::SecretKey::from_slice(&sk_bytes)
        .ok_or_else(|| anyhow!("Invalid recipient secret key"))?;

    // list remote directory
    let entries = sftp.readdir(std::path::Path::new(&chunks_dir))?;
    let mut files_map: HashMap<String, Vec<ChunkMeta>> = HashMap::new();
    for (p, _st) in entries.into_iter() {
        let name = match p.file_name().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        if name.is_empty() {
            continue;
        }
        if name.ends_with(".nonce") || name.ends_with(".sender") {
            continue;
        }

        if let Ok(mut l) = logs.lock() {
            l.push(format!("Downloading {}", name));
        }
        let remote_path = format!("{}/{}", chunks_dir, name);
        let encrypted = {
            let mut f = sftp.open(std::path::Path::new(&remote_path))?;
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            buf
        };

        let nonce_b64 = {
            let np = format!("{}.nonce", remote_path);
            let mut f = sftp.open(std::path::Path::new(&np))?;
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            String::from_utf8_lossy(&buf).to_string()
        };

        let sender_b64 = {
            let sp = format!("{}.sender", remote_path);
            let mut f = sftp.open(std::path::Path::new(&sp))?;
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            String::from_utf8_lossy(&buf).to_string()
        };

        let sender_bytes = general_purpose::STANDARD.decode(sender_b64.trim())?;
        let sender_pk = crypto::PublicKey::from_slice(&sender_bytes)
            .ok_or_else(|| anyhow!("Invalid sender public key"))?;

        if let Ok(mut l) = logs.lock() {
            l.push(format!("Decrypting {}", name));
        }
        let json = crypto::decrypt_chunk(&encrypted, nonce_b64.trim(), &sender_pk, &recipient_sk)?;
        let meta: ChunkMeta = serde_json::from_slice(&json)?;
        files_map.entry(meta.file_sha256.clone()).or_default().push(meta);
    }

    for (_sha, mut metas) in files_map {
        metas.sort_by_key(|m| m.chunk_index);
        if let Ok(mut l) = logs.lock() {
            l.push(format!(
                "Assembling file {} ({} chunks)",
                metas
                    .first()
                    .map(|m| m.file_name.clone())
                    .unwrap_or_default(),
                metas.len()
            ));
        }
        let assembled = chunk::assemble_file_from_chunks(&metas)?;
        chunk::verify_file_integrity(&metas, &assembled)?;

        if let Some(first) = metas.first() {
            let out_path = output_root.join(&first.file_name);
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            write_bytes_to_file(&out_path, &assembled)?;
            if let Ok(mut l) = logs.lock() {
                l.push(format!("Wrote {}", out_path.display()));
            }
        }
    }

    if let Ok(mut l) = logs.lock() {
        l.push("Assembly finished".to_string());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn assemble_from_sftp_with_logs_auth(
    host: &str,
    username: &str,
    password: Option<&str>,
    private_key: Option<&str>,
    private_key_pass: Option<&str>,
    expected_host_fp_sha256_b64: Option<&str>,
    remote_base: &str,
    recipient_id: &str,
    recipient_sk_b64: &str,
    output_root: &Path,
    logs: Arc<Mutex<Vec<String>>>
) -> Result<()> {
    let auth = match (private_key, password) {
        (Some(pk), _) => SshAuth::Key { private_key: pk, passphrase: private_key_pass },
        (None, Some(pw)) => SshAuth::Password(pw),
        _ => return Err(anyhow!("No SSH auth provided")),
    };
    let (sftp, _sess, _tcp) = sftp_connect_with(host, username, auth, expected_host_fp_sha256_b64)?;
    let chunks_dir = format!("{}/{}/chunks", remote_base.trim_end_matches('/'), recipient_id);

    // parse recipient secret key
    let sk_bytes = general_purpose::STANDARD.decode(recipient_sk_b64)?;
    let recipient_sk = crypto::SecretKey::from_slice(&sk_bytes)
        .ok_or_else(|| anyhow!("Invalid recipient secret key"))?;

    let entries = sftp.readdir(std::path::Path::new(&chunks_dir))?;
    let mut files_map: HashMap<String, Vec<ChunkMeta>> = HashMap::new();
    for (p, _st) in entries.into_iter() {
        let name = match p.file_name().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        if name.is_empty() { continue; }
        if name.ends_with(".nonce") || name.ends_with(".sender") { continue; }

        if let Ok(mut l) = logs.lock() { l.push(format!("Downloading {}", name)); }
        let remote_path = format!("{}/{}", chunks_dir, name);
        let encrypted = {
            let mut f = sftp.open(std::path::Path::new(&remote_path))?;
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            buf
        };

        let nonce_b64 = {
            let np = format!("{}.nonce", remote_path);
            let mut f = sftp.open(std::path::Path::new(&np))?;
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            String::from_utf8_lossy(&buf).to_string()
        };

        let sender_b64 = {
            let sp = format!("{}.sender", remote_path);
            let mut f = sftp.open(std::path::Path::new(&sp))?;
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            String::from_utf8_lossy(&buf).to_string()
        };

        let sender_bytes = general_purpose::STANDARD.decode(sender_b64.trim())?;
        let sender_pk = crypto::PublicKey::from_slice(&sender_bytes)
            .ok_or_else(|| anyhow!("Invalid sender public key"))?;

        if let Ok(mut l) = logs.lock() { l.push(format!("Decrypting {}", name)); }
        let json = crypto::decrypt_chunk(&encrypted, nonce_b64.trim(), &sender_pk, &recipient_sk)?;
        let meta: ChunkMeta = serde_json::from_slice(&json)?;
        files_map.entry(meta.file_sha256.clone()).or_default().push(meta);
    }

    for (_sha, mut metas) in files_map {
        metas.sort_by_key(|m| m.chunk_index);
        if let Ok(mut l) = logs.lock() {
            l.push(format!(
                "Assembling file {} ({} chunks)",
                metas.first().map(|m| m.file_name.clone()).unwrap_or_default(),
                metas.len()
            ));
        }
        let assembled = chunk::assemble_file_from_chunks(&metas)?;
        chunk::verify_file_integrity(&metas, &assembled)?;

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

#[allow(dead_code)]
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
