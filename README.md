# n0n

n0n is a cross-platform desktop utility for secure file splitting, per-chunk authenticated encryption, and mailbox-style storage. It supports a local backend and an SFTP backend with SSH key auth and host key fingerprint verification.

Quick start

- Run the GUI:

```powershell
cargo run
```

- In the app:
	- Generate a keypair (or paste an existing recipient public key).
	- Select a file or folder, set chunk size, output dir, and storage backend.
	- For SFTP, provide host (host:port), user, and either password or a private key path (with optional passphrase).
	- Optional but recommended: set the server SSH host key fingerprint (SHA-256 base64). Enable “Require host fingerprint” to enforce it.
	- Click “Split & Encrypt” to upload/save chunks into a recipient mailbox.
	- Use “Assemble & Decrypt” to reassemble files from a mailbox to the output dir.

Security bits

- Per-chunk crypto box semantics (X25519 + XSalsa20-Poly1305 via libsodium). Each chunk has a unique random nonce; the sender public key and nonce are stored alongside the encrypted chunk.
- The encrypted chunk filename is the SHA-256 of the ciphertext, enabling deduplication.
- SFTP: atomic upload (temp + rename). Optional strict host key verification (SHA-256 base64 of the raw SSH host key).

Tests

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
