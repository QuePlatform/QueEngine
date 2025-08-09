# Configuration and Features

Cargo Features
- c2pa (default): enable the C2PA adapter and all related APIs
- openssl (default): required by c2pa’s OpenSSL backend
- local: dev signer support (files/env)
- kms: reserved for QueCloud signer backend
- cloudhsm: reserved for QueCloud signer backend
- enclave: reserved for device signer backend (Secure Enclave/Keystore)
- wasm: reserved for future WASM build
- bmff: enable fragmented BMFF generation (pulls in `glob`)

Build Profiles (recommended)
- dev: features = c2pa, openssl, local
- server (QueCloud): features = c2pa, openssl, kms, cloudhsm (NO enclave)
- device: features = c2pa, openssl, enclave (NO kms/cloudhsm)

Environment and Files
- For Signer::Env: set two variables containing PEM strings
  - CERT_VAR, KEY_VAR
- For Signer::Local: use PEM file paths
- Timestamper:
  - digicert or custom:<url> injects `ta_url` in the manifest.

Security Notes
- Never commit keys. Tests generate keys in-memory.
- If you provide trust anchors, ensure they are pinned to your CA set and rotated out-of-band.
- Remote manifests can fetch from URLs during verification when enabled. Consider proxying or pinning via QueCloud.