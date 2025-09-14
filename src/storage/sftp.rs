use anyhow::{Result, anyhow};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, AtomicBool};
use std::io::{Read, Write};
use std::net::TcpStream;
use ssh2::Session;
use base64::{Engine as _, engine::general_purpose};
// Removed unused imports: chunk, ChunkMeta, crypto
// Removed unused imports: serde_json, rand

/// Connect to SFTP server with password authentication
pub fn sftp_connect(host: &str, username: &str, password: &str) -> Result<(ssh2::Sftp, Session, TcpStream)> {
    let tcp = TcpStream::connect(host)?;
    let mut sess = Session::new()?;
    sess.set_tcp_stream(tcp.try_clone()?);
    sess.handshake()?;
    sess.userauth_password(username, password)?;
    let sftp = sess.sftp()?;
    Ok((sftp, sess, tcp))
}

/// Connect to SFTP server with key-based authentication
#[allow(clippy::too_many_arguments)]
pub fn sftp_connect_auth(
    host: &str, 
    username: &str, 
    password: Option<&str>,
    private_key: Option<&str>,
    private_key_passphrase: Option<&str>,
    expected_host_fp_sha256_b64: Option<&str>
) -> Result<(ssh2::Sftp, Session, TcpStream)> {
    let tcp = TcpStream::connect(host)?;
    let mut sess = Session::new()?;
    sess.set_tcp_stream(tcp.try_clone()?);
    sess.handshake()?;

    // Check host key fingerprint if provided
    if let Some(expected_b64) = expected_host_fp_sha256_b64 {
        if let Some((hostkey, _typ)) = sess.host_key() {
            use sha2::{Digest, Sha256};
            let fp = Sha256::digest(hostkey);
            let got_b64 = general_purpose::STANDARD.encode(fp);
            // Allow optional padding differences by trimming '=' on both sides
            let exp_trim = expected_b64.trim_end_matches('=');
            let got_trim = got_b64.trim_end_matches('=');
            if exp_trim != got_trim {
                return Err(anyhow!("Host key fingerprint mismatch"));
            }
        }
    }

    // Authenticate
    if let Some(pk) = private_key {
        // Try private key authentication
        if pk.starts_with("-----BEGIN") {
            // PEM format key
            let temp_key_path = std::env::temp_dir().join("temp_ssh_key");
            std::fs::write(&temp_key_path, pk)?;
            let result = sess.userauth_pubkey_file(
                username, 
                None,
                &temp_key_path,
                private_key_passphrase
            );
            let _ = std::fs::remove_file(&temp_key_path); // cleanup
            result?;
        } else {
            // Assume it's a file path
            sess.userauth_pubkey_file(
                username,
                None, 
                std::path::Path::new(pk),
                private_key_passphrase
            )?;
        }
    } else if let Some(pw) = password {
        sess.userauth_password(username, pw)?;
    } else {
        return Err(anyhow!("No authentication method provided"));
    }

    let sftp = sess.sftp()?;
    Ok((sftp, sess, tcp))
}

/// Ensure a remote directory exists
fn ensure_remote_dir(sftp: &ssh2::Sftp, path: &str) -> Result<()> {
    // Try to create directory, ignore error if it already exists
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let mut current = String::new();
    
    for part in parts {
        current.push('/');
        current.push_str(part);
        let _ = sftp.mkdir(std::path::Path::new(&current), 0o755);
    }
    
    Ok(())
}

/// Check if a remote chunk exists
fn remote_chunk_exists(sftp: &ssh2::Sftp, remote_path: &str) -> bool {
    let p = std::path::Path::new(remote_path);
    sftp.stat(p).is_ok()
}

/// Upload a chunk to SFTP server
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
        // already exists, skip
        return Ok(());
    }

    // write chunk data (with temp name then rename for atomicity)
    let temp_path = format!("{}.tmp", remote_chunk_path);
    let temp_path_p = std::path::Path::new(&temp_path);
    {
        let mut remote_file = sftp.create(temp_path_p)?;
        remote_file.write_all(data)?;
        remote_file.flush()?;
    }
    sftp.rename(temp_path_p, remote_chunk_path_p, None)?;

    // write nonce and sender
    let nonce_path = format!("{}.nonce", remote_chunk_path);
    let sender_path = format!("{}.sender", remote_chunk_path);
    
    {
        let mut nonce_file = sftp.create(std::path::Path::new(&nonce_path))?;
        nonce_file.write_all(nonce_b64.as_bytes())?;
    }
    
    {
        let mut sender_file = sftp.create(std::path::Path::new(&sender_path))?;
        sender_file.write_all(sender_b64.as_bytes())?;
    }

    Ok(())
}

/// Test SFTP connection
pub fn test_sftp_connection(host: &str, username: &str, password: &str, remote_base: &str) -> Result<()> {
    let (_sftp, _sess, _tcp) = sftp_connect(host, username, password)?;
    // If we got here, connection was successful
    Ok(())
}

/// Test SFTP connection with authentication options
#[allow(clippy::too_many_arguments)]
pub fn test_sftp_connection_auth(
    host: &str,
    username: &str,
    password: Option<&str>,
    private_key: Option<&str>,
    private_key_pass: Option<&str>,
    expected_host_fp_sha256_b64: Option<&str>,
    remote_base: &str,
) -> Result<()> {
    let (_sftp, _sess, _tcp) = sftp_connect_auth(host, username, password, private_key, private_key_pass, expected_host_fp_sha256_b64)?;
    // If we got here, connection was successful
    Ok(())
}

/// Upload chunk with authentication options
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
    let (sftp, _sess, _tcp) = sftp_connect_auth(host, username, password, private_key, private_key_pass, expected_host_fp_sha256_b64)?;
    
    // ensure base/recipient/chunks exists
    let chunks_dir = format!("{}/{}/chunks", remote_base.trim_end_matches('/'), recipient);
    ensure_remote_dir(&sftp, &chunks_dir)?;

    let remote_chunk_path = format!("{}/{}", chunks_dir, sha);
    let remote_chunk_path_p = std::path::Path::new(&remote_chunk_path);
    if remote_chunk_exists(&sftp, &remote_chunk_path) {
        return Ok(());
    }

    // write chunk data (with temp name then rename for atomicity)
    let temp_path = format!("{}.tmp", remote_chunk_path);
    let temp_path_p = std::path::Path::new(&temp_path);
    {
        let mut remote_file = sftp.create(temp_path_p)?;
        remote_file.write_all(data)?;
        remote_file.flush()?;
    }
    sftp.rename(temp_path_p, remote_chunk_path_p, None)?;

    // write nonce and sender
    let nonce_path = format!("{}.nonce", remote_chunk_path);
    let sender_path = format!("{}.sender", remote_chunk_path);
    
    {
        let mut nonce_file = sftp.create(std::path::Path::new(&nonce_path))?;
        nonce_file.write_all(nonce_b64.as_bytes())?;
    }
    
    {
        let mut sender_file = sftp.create(std::path::Path::new(&sender_path))?;
        sender_file.write_all(sender_b64.as_bytes())?;
    }

    Ok(())
}

/// Process and encrypt a file to SFTP storage
#[allow(clippy::too_many_arguments)]
pub fn process_file_encrypt_to_sftp(
    file_path: &Path,
    root_folder: &Path,
    recipient_pk_b64: &str,
    mailbox_id: &str,
    sender_sk_b64: Option<&str>,
    host: &str,
    username: &str,
    password: &str,
    remote_base: &str,
    chunk_size_bytes: usize,
    progress: Option<(Arc<AtomicUsize>, Arc<AtomicUsize>)>,
    cancel: Option<Arc<AtomicBool>>,
) -> Result<()> {
    use crate::crypto::{PublicKey, SecretKey, encrypt_chunk};
    use crate::chunk::split_file_into_chunks;
    use base64::{Engine as _, engine::general_purpose};

    // Check for cancellation
    if let Some(ref cancel_flag) = cancel {
        if cancel_flag.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(anyhow!("Operation cancelled"));
        }
    }

    // Parse crypto keys
    let recipient_pk = PublicKey::from_slice(&general_purpose::STANDARD.decode(recipient_pk_b64)?)
        .ok_or_else(|| anyhow!("Invalid recipient public key"))?;

    let sender_sk = if let Some(sk_b64) = sender_sk_b64 {
        SecretKey::from_slice(&general_purpose::STANDARD.decode(sk_b64)?)
            .ok_or_else(|| anyhow!("Invalid sender secret key"))?
    } else {
        return Err(anyhow!("Sender secret key required for encryption"));
    };

    // Get relative path for chunking
    let relative_path = file_path.strip_prefix(root_folder)
        .unwrap_or(file_path)
        .to_string_lossy()
        .to_string();

    // Split file into chunks
    let chunks = split_file_into_chunks(file_path, chunk_size_bytes, &relative_path)?;

    // Connect to SFTP
    let (sftp, _sess, _tcp) = sftp_connect(host, username, password)?;

    // Ensure remote directory exists
    ensure_remote_dir(&sftp, &format!("{}/{}", remote_base, mailbox_id))?;

    let total_chunks = chunks.len();

    for (i, chunk) in chunks.iter().enumerate() {
        // Check for cancellation
        if let Some(ref cancel_flag) = cancel {
            if cancel_flag.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(anyhow!("Operation cancelled"));
            }
        }

        // Read chunk data
        let chunk_data = std::fs::read(&chunk.path)?;

        // Encrypt chunk
        let (encrypted_data, nonce) = encrypt_chunk(&chunk_data, &recipient_pk, &sender_sk)?;

        // Create chunk filename
        let chunk_filename = format!("{}/{}/{}.enc", remote_base, mailbox_id, chunk.hash);

        // Upload encrypted chunk
        let mut remote_file = sftp.create(Path::new(&chunk_filename))?;
        remote_file.write_all(&encrypted_data)?;

        // Create metadata file
        let metadata = serde_json::json!({
            "hash": chunk.hash,
            "size": chunk.size,
            "nonce": nonce,
            "relative_path": chunk.relative_path,
            "chunk_index": chunk.index
        });

        let metadata_filename = format!("{}/{}/{}.meta", remote_base, mailbox_id, chunk.hash);
        let mut meta_file = sftp.create(Path::new(&metadata_filename))?;
        meta_file.write_all(metadata.to_string().as_bytes())?;

        // Update progress
        if let Some((ref current, ref total)) = progress {
            current.store(i + 1, std::sync::atomic::Ordering::Relaxed);
            total.store(total_chunks, std::sync::atomic::Ordering::Relaxed);
        }

        log::debug!("Uploaded encrypted chunk {}/{}: {}", i + 1, total_chunks, chunk.hash);
    }

    log::info!("Successfully encrypted and uploaded {} chunks to SFTP", total_chunks);
    Ok(())
}

/// Process and encrypt a file to SFTP storage with authentication
#[allow(clippy::too_many_arguments)]
pub fn process_file_encrypt_to_sftp_auth(
    file_path: &Path,
    root_folder: &Path,
    recipient_pk_b64: &str,
    mailbox_id: &str,
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
    use crate::crypto::{PublicKey, SecretKey, encrypt_chunk};
    use crate::chunk::split_file_into_chunks;
    use base64::{Engine as _, engine::general_purpose};

    // Check for cancellation
    if let Some(ref cancel_flag) = cancel {
        if cancel_flag.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(anyhow!("Operation cancelled"));
        }
    }

    // Parse crypto keys
    let recipient_pk = PublicKey::from_slice(&general_purpose::STANDARD.decode(recipient_pk_b64)?)
        .ok_or_else(|| anyhow!("Invalid recipient public key"))?;

    let sender_sk = if let Some(sk_b64) = sender_sk_b64 {
        SecretKey::from_slice(&general_purpose::STANDARD.decode(sk_b64)?)
            .ok_or_else(|| anyhow!("Invalid sender secret key"))?
    } else {
        return Err(anyhow!("Sender secret key required for encryption"));
    };

    // Get relative path for chunking
    let relative_path = file_path.strip_prefix(root_folder)
        .unwrap_or(file_path)
        .to_string_lossy()
        .to_string();

    // Split file into chunks
    let chunks = split_file_into_chunks(file_path, chunk_size_bytes, &relative_path)?;

    // Connect to SFTP with authentication
    let (sftp, _sess, _tcp) = sftp_connect_auth(
        host,
        username,
        password,
        private_key,
        private_key_pass,
        expected_host_fp_sha256_b64
    )?;

    // Ensure remote directory exists
    ensure_remote_dir(&sftp, &format!("{}/{}", remote_base, mailbox_id))?;

    let total_chunks = chunks.len();

    for (i, chunk) in chunks.iter().enumerate() {
        // Check for cancellation
        if let Some(ref cancel_flag) = cancel {
            if cancel_flag.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(anyhow!("Operation cancelled"));
            }
        }

        // Read chunk data
        let chunk_data = std::fs::read(&chunk.path)?;

        // Encrypt chunk
        let (encrypted_data, nonce) = encrypt_chunk(&chunk_data, &recipient_pk, &sender_sk)?;

        // Create chunk filename
        let chunk_filename = format!("{}/{}/{}.enc", remote_base, mailbox_id, chunk.hash);

        // Upload encrypted chunk
        let mut remote_file = sftp.create(Path::new(&chunk_filename))?;
        remote_file.write_all(&encrypted_data)?;

        // Create metadata file
        let metadata = serde_json::json!({
            "hash": chunk.hash,
            "size": chunk.size,
            "nonce": nonce,
            "relative_path": chunk.relative_path,
            "chunk_index": chunk.index
        });

        let metadata_filename = format!("{}/{}/{}.meta", remote_base, mailbox_id, chunk.hash);
        let mut meta_file = sftp.create(Path::new(&metadata_filename))?;
        meta_file.write_all(metadata.to_string().as_bytes())?;

        // Update progress
        if let Some((ref current, ref total)) = progress {
            current.store(i + 1, std::sync::atomic::Ordering::Relaxed);
            total.store(total_chunks, std::sync::atomic::Ordering::Relaxed);
        }

        log::debug!("Uploaded encrypted chunk {}/{}: {}", i + 1, total_chunks, chunk.hash);
    }

    log::info!("Successfully encrypted and uploaded {} chunks to SFTP with auth", total_chunks);
    Ok(())
}

/// Download a file from SFTP server
#[allow(clippy::too_many_arguments)]
pub fn download_remote_file(host: &str, username: &str, password: &str, remote_path: &str) -> Result<Vec<u8>> {
    let (sftp, _sess, _tcp) = sftp_connect(host, username, password)?;
    
    let mut file = sftp.open(std::path::Path::new(remote_path))?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    Ok(contents)
}

/// Assemble files from SFTP with logging
#[allow(clippy::too_many_arguments)]
pub fn assemble_from_sftp_with_logs(
    host: &str,
    username: &str,
    password: &str,
    remote_base: &str,
    recipient_sk_b64: &str,
    output_root: &Path,
    recipient_pk_b64: &str,
    logs: Arc<Mutex<Vec<String>>>
) -> Result<()> {
    use crate::crypto::{PublicKey, SecretKey, decrypt_chunk};
    use base64::{Engine as _, engine::general_purpose};
    use std::collections::HashMap;

    if let Ok(mut l) = logs.lock() {
        l.push(format!("Starting SFTP assembly from {}@{}", username, host));
    }

    // Parse crypto keys
    let recipient_sk = SecretKey::from_slice(&general_purpose::STANDARD.decode(recipient_sk_b64)?)
        .ok_or_else(|| anyhow!("Invalid recipient secret key"))?;

    let sender_pk = PublicKey::from_slice(&general_purpose::STANDARD.decode(recipient_pk_b64)?)
        .ok_or_else(|| anyhow!("Invalid sender public key"))?;

    // Connect to SFTP
    let (sftp, _sess, _tcp) = sftp_connect(host, username, password)?;

    if let Ok(mut l) = logs.lock() {
        l.push("Connected to SFTP server".to_string());
    }

    // List all .enc files in the remote directory
    let remote_dir = std::path::Path::new(remote_base);
    let dir_listing = sftp.readdir(remote_dir)?;

    let mut chunks: HashMap<String, (Vec<u8>, serde_json::Value)> = HashMap::new();

    for (path, _stat) in dir_listing {
        let filename = path.file_name().unwrap_or_default().to_string_lossy();

        if filename.ends_with(".enc") {
            let chunk_hash = filename.strip_suffix(".enc").unwrap();

            // Read encrypted chunk
            let mut chunk_file = sftp.open(&path)?;
            let mut encrypted_data = Vec::new();
            chunk_file.read_to_end(&mut encrypted_data)?;

            // Read corresponding metadata
            let meta_path = path.with_extension("meta");
            if let Ok(mut meta_file) = sftp.open(&meta_path) {
                let mut meta_content = String::new();
                meta_file.read_to_string(&mut meta_content)?;

                if let Ok(metadata) = serde_json::from_str::<serde_json::Value>(&meta_content) {
                    chunks.insert(chunk_hash.to_string(), (encrypted_data, metadata));

                    if let Ok(mut l) = logs.lock() {
                        l.push(format!("Found encrypted chunk: {}", chunk_hash));
                    }
                }
            }
        }
    }

    if let Ok(mut l) = logs.lock() {
        l.push(format!("Found {} encrypted chunks", chunks.len()));
    }

    // Decrypt and reassemble chunks by file
    let mut files_by_path: HashMap<String, Vec<(usize, Vec<u8>)>> = HashMap::new();

    for (chunk_hash, (encrypted_data, metadata)) in chunks {
        if let (Some(nonce), Some(relative_path), Some(chunk_index)) = (
            metadata.get("nonce").and_then(|v| v.as_str()),
            metadata.get("relative_path").and_then(|v| v.as_str()),
            metadata.get("chunk_index").and_then(|v| v.as_u64())
        ) {
            // Decrypt chunk
            match decrypt_chunk(&encrypted_data, nonce, &sender_pk, &recipient_sk) {
                Ok(decrypted_data) => {
                    files_by_path.entry(relative_path.to_string())
                        .or_insert_with(Vec::new)
                        .push((chunk_index as usize, decrypted_data));

                    if let Ok(mut l) = logs.lock() {
                        l.push(format!("Decrypted chunk {} for {}", chunk_hash, relative_path));
                    }
                }
                Err(e) => {
                    if let Ok(mut l) = logs.lock() {
                        l.push(format!("Failed to decrypt chunk {}: {}", chunk_hash, e));
                    }
                }
            }
        }
    }

    // Write reassembled files
    for (relative_path, mut file_chunks) in files_by_path {
        // Sort chunks by index
        file_chunks.sort_by_key(|(index, _)| *index);

        let output_path = output_root.join(&relative_path);

        // Create parent directories
        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Write file
        let mut output_file = std::fs::File::create(&output_path)?;
        for (_, chunk_data) in file_chunks {
            output_file.write_all(&chunk_data)?;
        }

        if let Ok(mut l) = logs.lock() {
            l.push(format!("Reassembled file: {}", relative_path));
        }
    }

    if let Ok(mut l) = logs.lock() {
        l.push("SFTP assembly completed successfully".to_string());
    }

    Ok(())
}

/// Assemble files from SFTP with authentication and logging
#[allow(clippy::too_many_arguments)]
pub fn assemble_from_sftp_with_logs_auth(
    host: &str,
    username: &str,
    password: Option<&str>,
    private_key: Option<&str>,
    private_key_pass: Option<&str>,
    expected_host_fp_sha256_b64: Option<&str>,
    remote_base: &str,
    recipient_sk_b64: &str,
    output_root: &Path,
    recipient_pk_b64: &str,
    logs: Arc<Mutex<Vec<String>>>
) -> Result<()> {
    use crate::crypto::{PublicKey, SecretKey, decrypt_chunk};
    use base64::{Engine as _, engine::general_purpose};
    use std::collections::HashMap;

    if let Ok(mut l) = logs.lock() {
        l.push(format!("Starting SFTP auth assembly from {}@{}", username, host));
    }

    // Parse crypto keys
    let recipient_sk = SecretKey::from_slice(&general_purpose::STANDARD.decode(recipient_sk_b64)?)
        .ok_or_else(|| anyhow!("Invalid recipient secret key"))?;

    let sender_pk = PublicKey::from_slice(&general_purpose::STANDARD.decode(recipient_pk_b64)?)
        .ok_or_else(|| anyhow!("Invalid sender public key"))?;

    // Connect to SFTP with authentication
    let (sftp, _sess, _tcp) = sftp_connect_auth(
        host,
        username,
        password,
        private_key,
        private_key_pass,
        expected_host_fp_sha256_b64
    )?;

    if let Ok(mut l) = logs.lock() {
        l.push("Connected to SFTP server with authentication".to_string());
    }

    // List all .enc files in the remote directory
    let remote_dir = std::path::Path::new(remote_base);
    let dir_listing = sftp.readdir(remote_dir)?;

    let mut chunks: HashMap<String, (Vec<u8>, serde_json::Value)> = HashMap::new();

    for (path, _stat) in dir_listing {
        let filename = path.file_name().unwrap_or_default().to_string_lossy();

        if filename.ends_with(".enc") {
            let chunk_hash = filename.strip_suffix(".enc").unwrap();

            // Read encrypted chunk
            let mut chunk_file = sftp.open(&path)?;
            let mut encrypted_data = Vec::new();
            chunk_file.read_to_end(&mut encrypted_data)?;

            // Read corresponding metadata
            let meta_path = path.with_extension("meta");
            if let Ok(mut meta_file) = sftp.open(&meta_path) {
                let mut meta_content = String::new();
                meta_file.read_to_string(&mut meta_content)?;

                if let Ok(metadata) = serde_json::from_str::<serde_json::Value>(&meta_content) {
                    chunks.insert(chunk_hash.to_string(), (encrypted_data, metadata));

                    if let Ok(mut l) = logs.lock() {
                        l.push(format!("Found encrypted chunk: {}", chunk_hash));
                    }
                }
            }
        }
    }

    if let Ok(mut l) = logs.lock() {
        l.push(format!("Found {} encrypted chunks", chunks.len()));
    }

    // Decrypt and reassemble chunks by file
    let mut files_by_path: HashMap<String, Vec<(usize, Vec<u8>)>> = HashMap::new();

    for (chunk_hash, (encrypted_data, metadata)) in chunks {
        if let (Some(nonce), Some(relative_path), Some(chunk_index)) = (
            metadata.get("nonce").and_then(|v| v.as_str()),
            metadata.get("relative_path").and_then(|v| v.as_str()),
            metadata.get("chunk_index").and_then(|v| v.as_u64())
        ) {
            // Decrypt chunk
            match decrypt_chunk(&encrypted_data, nonce, &sender_pk, &recipient_sk) {
                Ok(decrypted_data) => {
                    files_by_path.entry(relative_path.to_string())
                        .or_insert_with(Vec::new)
                        .push((chunk_index as usize, decrypted_data));

                    if let Ok(mut l) = logs.lock() {
                        l.push(format!("Decrypted chunk {} for {}", chunk_hash, relative_path));
                    }
                }
                Err(e) => {
                    if let Ok(mut l) = logs.lock() {
                        l.push(format!("Failed to decrypt chunk {}: {}", chunk_hash, e));
                    }
                }
            }
        }
    }

    // Write reassembled files
    for (relative_path, mut file_chunks) in files_by_path {
        // Sort chunks by index
        file_chunks.sort_by_key(|(index, _)| *index);

        let output_path = output_root.join(&relative_path);

        // Create parent directories
        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Write file
        let mut output_file = std::fs::File::create(&output_path)?;
        for (_, chunk_data) in file_chunks {
            output_file.write_all(&chunk_data)?;
        }

        if let Ok(mut l) = logs.lock() {
            l.push(format!("Reassembled file: {}", relative_path));
        }
    }

    if let Ok(mut l) = logs.lock() {
        l.push("SFTP auth assembly completed successfully".to_string());
    }

    Ok(())
}