# CRYPTA — AES-256-GCM Security Workbench

A Flask-based educational cryptography application packaged with Docker. It supports authenticated encryption and decryption of text, individual files, and folders.

## Features
- AES-256-GCM authenticated encryption.
- PBKDF2-HMAC-SHA256 passphrase derivation (600,000 iterations).
- Fresh 16-byte salt and 12-byte nonce for every encryption.
- Text payloads encoded in Base64.
- Binary file encryption to `.aes` downloads.
- Folder encryption/decryption through ZIP archives while retaining relative paths.
- SHA-256 helper for integrity comparison in local validation workflows.
- Input validation, safe archive path checks, upload limits and security response headers.
- Docker runs as a non-root user with a read-only root filesystem, dropped capabilities and localhost-only port binding.
- pytest test suite.

## Run on Windows
1. Start Docker Desktop.
2. Extract this folder and open PowerShell in it.
3. Run `docker compose up --build -d`.
4. Open `http://127.0.0.1:5000`.
5. Health check: `curl.exe http://127.0.0.1:5000/api/health`.
6. Stop: `docker compose down`.

## Run tests locally
Install requirements, then run `pytest -q`.

## Encryption format
File envelope: `AESFILE1` (8-byte header) + 16-byte salt + 12-byte nonce + AES-GCM ciphertext and 16-byte authentication tag. The header is authenticated as associated data. Text uses a versioned `AESTEXT1` Base64 representation.

## Folder workflow
Each selected file is encrypted independently and placed in a ZIP with `.aes` appended to its relative path. Decryption verifies every entry before returning a restored ZIP. Extract the returned ZIP only after verifying that it came from a trusted local operation.

## Important notes
This is a classroom prototype, not a production service. Do not expose it to the public internet or use sensitive personal or organizational data. The application processes uploads in memory and is intended for modest test files. Keep passphrases safe; lost passphrases cannot be recovered. A successful GCM tag verifies ciphertext integrity under the supplied key, but does not establish the identity or provenance of the file.
