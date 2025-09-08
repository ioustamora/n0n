#![cfg(feature = "sftp-tests")]
use n0n::{crypto, storage};
use base64::{engine::general_purpose, Engine as _};
use std::env;

fn env_ok(keys: &[&str]) -> Option<Vec<String>> {
    let mut vals = Vec::new();
    for k in keys {
        match env::var(k) {
            Ok(v) if !v.trim().is_empty() => vals.push(v),
            _ => return None,
        }
    }
    Some(vals)
}

#[test]
fn sftp_roundtrip_password_or_key() {
    // Require host, user, base, mailbox id; either password or key path; host fp optional but recommended
    let keys = [
        "N0N_SFTP_HOST", "N0N_SFTP_USER", "N0N_SFTP_BASE", "N0N_SFTP_MAILBOX",
    ];
    let Some(base_vals) = env_ok(&keys) else { eprintln!("skipping: missing base env vars"); return; };
    let host = base_vals[0].clone();
    let user = base_vals[1].clone();
    let remote_base = base_vals[2].clone();
    let mailbox = base_vals[3].clone();
    let password = env::var("N0N_SFTP_PASSWORD").ok();
    let key_path = env::var("N0N_SSH_KEY").ok();
    let key_pass = env::var("N0N_SSH_KEY_PASS").ok();
    let host_fp = env::var("N0N_SSH_HOST_FP_SHA256_B64").ok();
    if password.as_deref().unwrap_or("").is_empty() && key_path.as_deref().unwrap_or("").is_empty() {
        eprintln!("skipping: neither password nor key provided");
        return;
    }

    crypto::init();
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    let file = src.join("hello.txt");
    std::fs::write(&file, b"hello sftp").unwrap();

    // recipient keys
    let (pk, sk) = crypto::generate_keypair();
    let pk_b64 = general_purpose::STANDARD.encode(&pk.0);
    let sk_b64 = general_purpose::STANDARD.encode(&sk.0);

    // encrypt to SFTP
    let chunk_size = 1024usize;
    if key_path.is_some() || host_fp.is_some() {
        let _ = storage::process_file_encrypt_to_sftp_auth(
            &file, &src, &pk_b64, &mailbox,
            None,
            &host, &user,
            password.as_deref(),
            key_path.as_deref(),
            key_pass.as_deref(),
            host_fp.as_deref(),
            &remote_base,
            chunk_size,
            None,
            None,
        ).unwrap();
    } else {
        let pw = password.expect("password required if not using key");
        let _ = storage::process_file_encrypt_to_sftp(
            &file, &src, &pk_b64, &mailbox,
            None,
            &host, &user, &pw, &remote_base,
            chunk_size,
            None,
            None,
        ).unwrap();
    }

    // assemble back from SFTP
    let out = tmp.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    if key_path.is_some() || host_fp.is_some() {
        let _ = storage::assemble_from_sftp_with_logs_auth(
            &host, &user,
            password.as_deref(),
            key_path.as_deref(),
            key_pass.as_deref(),
            host_fp.as_deref(),
            &remote_base,
            &mailbox,
            &sk_b64,
            &out,
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        ).unwrap();
    } else {
        let pw = env::var("N0N_SFTP_PASSWORD").unwrap();
        let _ = storage::assemble_from_sftp_with_logs(
            &host, &user, &pw,
            &remote_base,
            &mailbox,
            &sk_b64,
            &out,
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        ).unwrap();
    }

    let round = std::fs::read(out.join("hello.txt")).unwrap();
    assert_eq!(round, b"hello sftp");
}
