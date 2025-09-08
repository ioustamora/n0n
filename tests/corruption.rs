use n0n::{storage, crypto};
use tempfile::tempdir;
use base64::{engine::general_purpose, Engine as _};

#[test]
fn test_corrupted_ciphertext_fails() {
    crypto::init();

    // Prepare temp layout and file
    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    let file = src.join("data.bin");
    // Large enough to produce at least one chunk
    std::fs::write(&file, b"some test data that will be encrypted").unwrap();

    // Recipient keys
    let (recipient_pk, recipient_sk) = crypto::generate_keypair();
    let recipient_pk_b64 = general_purpose::STANDARD.encode(&recipient_pk.0);
    let recipient_sk_b64 = general_purpose::STANDARD.encode(&recipient_sk.0);

    // Mailbox base
    let mailbox_root = dir.path().join("mailbox");
    std::fs::create_dir_all(&mailbox_root).unwrap();

    // Encrypt into mailbox
    storage::process_file_encrypt(&file, &src, &recipient_pk_b64, None, &mailbox_root, 0, None, None).unwrap();

    // Find a ciphertext file and corrupt it
    let mailbox = mailbox_root.join(&recipient_pk_b64).join("chunks");
    let mut corrupted = false;
    for entry in std::fs::read_dir(&mailbox).unwrap() {
        let entry = entry.unwrap();
        let p = entry.path();
        // pick a file without extension (actual chunk)
        if p.extension().is_none() {
            let mut data = std::fs::read(&p).unwrap();
            if !data.is_empty() {
                data[0] ^= 0xFF; // flip first byte
            } else {
                data.push(0xFF);
            }
            std::fs::write(&p, &data).unwrap();
            corrupted = true;
            break;
        }
    }
    assert!(corrupted, "no chunk found to corrupt");

    // Attempt to assemble -> expect error due to decryption/MAC failure
    let out = dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    let res = storage::assemble_from_mailbox(&mailbox_root.join(&recipient_pk_b64), &recipient_sk_b64, &out);
    assert!(res.is_err(), "assembly should fail when ciphertext is corrupted");
}

#[test]
fn test_save_chunk_local_dedup() {
    use n0n::storage::save_chunk_local;
    // Prepare temp mailbox with chunks dir
    let dir = tempdir().unwrap();
    let mailbox = dir.path().join("mb");
    std::fs::create_dir_all(mailbox.join("chunks")).unwrap();

    // Two identical encrypted payloads
    let payload = b"ciphertext-bytes";
    let sha1 = save_chunk_local(&mailbox, payload).unwrap();
    let sha2 = save_chunk_local(&mailbox, payload).unwrap();
    assert_eq!(sha1, sha2);

    // Ensure only one file exists
    let chunk_path = mailbox.join("chunks").join(&sha1);
    assert!(chunk_path.exists());

    // Count files without extensions in chunks dir
    let mut count = 0;
    for entry in std::fs::read_dir(mailbox.join("chunks")).unwrap() {
        let entry = entry.unwrap();
        let p = entry.path();
        if p.is_file() && p.extension().is_none() { count += 1; }
    }
    assert_eq!(count, 1, "only one chunk file should be present");
}
