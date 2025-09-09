use crate::utils::{create_dir_if_not_exists, compute_sha256, write_bytes_to_file};
use anyhow::Result;
use std::path::{Path, PathBuf};

/// Ensure a mailbox directory exists for a recipient
pub fn ensure_mailbox_local(base: &Path, recipient: &str) -> Result<PathBuf> {
    let mailbox = base.join(recipient);
    create_dir_if_not_exists(&mailbox)?;
    Ok(mailbox)
}

/// Save an encrypted chunk to local storage
/// Returns the SHA-256 hash of the encrypted data (used as filename)
pub fn save_chunk_local(mailbox: &Path, encrypted: &[u8]) -> Result<String> {
    // filename is sha256 of encrypted data
    let hash = compute_sha256(encrypted);
    let chunks_dir = mailbox.join("chunks");
    create_dir_if_not_exists(&chunks_dir)?;
    
    let path = chunks_dir.join(&hash);
    write_bytes_to_file(&path, encrypted)?;
    
    Ok(hash)
}