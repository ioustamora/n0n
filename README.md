# n0n

n0n is a cross-platform desktop utility for secure file splitting, per-chunk authenticated encryption, and mailbox-style storage. It supports a local backend and an SFTP backend with SSH key auth and host key fingerprint verification.

## Features

- Per-chunk authenticated public-key encryption (crypto_box semantics via libsodium: X25519 + XSalsa20-Poly1305). Unique random nonce per chunk; sender public key stored alongside each chunk.
- Mailbox-per-recipient storage layout with deduplication by ciphertext SHA-256.
- Local storage and SFTP storage (atomic upload: temp + rename).
- GUI with file/folder selection, key management, chunk size, output directory, progress, pause/resume, cancel, and logs.
- Dry-run mode (no writes) with realistic progress simulation.
- Folder watcher with configurable debounce and “skip hidden” option.
- Search (local) for chunks by SHA-256.
- SFTP “Test Connection” button with optional host fingerprint verification.

## Quick start

- Run the GUI:

```powershell
cargo run
```

- In the app:
	- Generate a keypair (or paste an existing recipient public key).
	- Select a file or folder, set chunk size (MB), output dir, and storage backend.
	- For SFTP, provide host (host:port), user, and either password or a private key (with optional passphrase).
	- Optional but recommended: set the server SSH host key fingerprint (SHA-256 base64). Enable “Require host fingerprint” to enforce it.
	- Use “Test SFTP Connection” to verify authentication and host fingerprint before running.
	- Click “Split & Encrypt” to save/upload chunks to the recipient mailbox.
	- Use “Assemble & Decrypt” to reassemble files from a mailbox to the output dir.
	- Dry-run (no write): simulate processing and progress without writing or uploading chunks.
	- Watcher: start/stop; configure debounce (ms) to reduce duplicate events; respects “skip hidden”.
	- Settings: Save/Load non-secret preferences to a JSON file.

## Security model

- Each chunk’s plaintext JSON metadata is encrypted with crypto_box using a fresh random nonce and the recipient’s public key (sender uses an ephemeral or provided secret key). The sender’s public key and the nonce are stored as separate sidecar files so the recipient can decrypt.
- Chunk filename is the SHA-256 of the ciphertext; this enables deduplication without leaking plaintext metadata. Only nonce and sender public key are stored in the clear as sidecars.
- SFTP uploads are atomic (temp upload + rename). Optionally enforce SSH host key verification by comparing a SHA-256 base64 fingerprint of the server’s host key.

### Computing the SSH host key fingerprint (SHA-256 base64)

- With OpenSSH tools (Windows/macOS/Linux):

```powershell
# Prints lines like: <algo> SHA256:<base64> <host>
ssh-keyscan -t rsa,ed25519 your.host | ssh-keygen -lf - -E sha256
```

- Copy the base64 part after `SHA256:` (padding `=` is optional). Paste it into “Host key SHA-256 (base64)” and optionally enable “Require host fingerprint”.

## Storage layout

Mailbox layout under the chosen backend base path:

```
<base>/<recipient_id>/
	chunks/
		<sha256_of_ciphertext>
		<sha>.nonce   # base64-encoded nonce
		<sha>.sender  # base64-encoded sender public key
```

The `<recipient_id>` defaults to the recipient public key string (base64) unless a Mailbox ID is provided.

## Chunk JSON schema (encrypted)

The following JSON is produced per chunk, then encrypted (the recipient decrypts during assembly):

- file_name: original relative path
- file_size: original file length (bytes)
- file_sha256: SHA-256 of the whole file
- chunk_index: 0-based chunk number
- chunk_count: total number of chunks
- chunk_plain_sha256: SHA-256 of the plaintext chunk data
- all_chunks: list of chunk ciphertext SHA-256s for the file
- nonce: base64-encoded nonce used for this chunk
- data: base64 of the plaintext chunk (inside JSON before encryption)

## GUI tips

- Pause/Resume and Cancel control the current job.
- Dry-run simulates estimated chunks and updates status, with no disk or network writes.
- Watcher debounce is configurable (default 750 ms) to reduce duplicate events per path.
- Output dir has Browse and Open buttons (opens your system file explorer).
- “Estimate Chunks” computes the total chunks for the current selection and displays/logs it.
- Settings Save/Load stores non-secrets (keys’ public parts, paths, options). Passwords and private key passphrases are not saved.

## Tests

- Unit/integration tests:

```powershell
cargo test
```

- Optional SFTP integration test (requires a reachable SFTP server):

```powershell
# set env vars appropriately
$env:N0N_SFTP_HOST = 'host:22'
$env:N0N_SFTP_USER = 'user'
$env:N0N_SFTP_PASSWORD = 'pass'   # or use key
# optional key-based auth
# $env:N0N_SSH_KEY = 'C:\\path\\to\\id_ed25519'
# $env:N0N_SSH_KEY_PASS = 'optional-passphrase'
# optional host fingerprint (base64 SHA-256)
# $env:N0N_SSH_HOST_FP_SHA256_B64 = '...'
$env:N0N_SFTP_BASE = '/remote/base/path'
$env:N0N_SFTP_MAILBOX = 'recipient-id'

cargo test --features sftp-tests --test sftp_integration -- --nocapture
```

## Build from source

- Requirements: Rust (stable). The project uses egui/eframe for the GUI and sodiumoxide for crypto (libsodium is built via the crate; no manual install typically required).

## License

This project is licensed under the terms of the LICENSE file included in this repository.
