use n0n::{storage, crypto};
use tempfile::tempdir;
use base64::{engine::general_purpose, Engine as _};

#[test]
fn test_encrypt_and_assemble_roundtrip() {
    // init
    crypto::init();

    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    let file = src.join("hello.txt");
    std::fs::write(&file, b"hello roundtrip").unwrap();

    // generate recipient keypair
    let (recipient_pk, recipient_sk) = crypto::generate_keypair();
    let recipient_pk_b64 = general_purpose::STANDARD.encode(&recipient_pk.0);
    let recipient_sk_b64 = general_purpose::STANDARD.encode(&recipient_sk.0);

    let mailbox = dir.path().join("mailbox");
    std::fs::create_dir_all(&mailbox).unwrap();

    // encrypt
    storage::process_file_encrypt(&file, &src, &recipient_pk_b64, None, &mailbox).unwrap();

    // assemble
    let out = dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    storage::assemble_from_mailbox(&mailbox, &recipient_sk_b64, &out).unwrap();

    let restored = std::fs::read(out.join("hello.txt")).unwrap();
    assert_eq!(restored, b"hello roundtrip");
}
