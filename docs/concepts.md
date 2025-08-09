# Concepts

AssetRef
- Path: a filesystem path
- Bytes: in-memory bytes plus optional extension hint `ext`
- For byte inputs, the engine writes a temp file so the C2PA builder/reader can operate.
- Extension hint: if provided (e.g., "png", "jpg", "mp4"), it helps the adapter choose the correct media handling path.

OutputTarget
- Path: write a signed asset to a path you control
- Memory: write to a temporary path, then return the resulting bytes
- Note: for `OutputTarget::Memory`, the temporary output’s extension currently defaults to “output_asset” (no extension). Some C2PA media handlers rely on file extension; if you need exact format-specific behavior, prefer Path output.

Signer
- Current sources:
  - local:/path/to/cert.pem,/path/to/key.pem
  - env:CERT_VAR,KEY_VAR
- KMS/HSM/Secure Enclave backends will be added behind features (`kms`, `cloudhsm`, `enclave`) and injected by QueCloud.
- Key material stays outside the engine; the engine asks a signer to produce signatures. In Local/Env modes you are responsible for key protection.

Timestamper
- digicert: injects `ta_url` = http://timestamp.digicert.com
- custom:<url>: injects a custom TSA URL
- The TSA URL is injected into the manifest JSON before building.

C2PA Settings Isolation
- The upstream c2pa library uses global process-wide settings. QueEngine wraps any settings mutation under a global mutex and resets to baseline after each call.
- Implication: sign/verify operations that touch settings are serialized to avoid cross-talk. You can run many engine calls concurrently, but the settings sections execute one at a time.

Policy and Trust
- Verification accepts an optional `TrustPolicyConfig`:
  - anchors: PEM trust anchors (bytes)
  - allowed_list: PEM list of allowed leaf certs
  - allowed_ekus: EKU OIDs allowed in the signing certificate
- If no policy is provided, `verify_trust` is disabled. This means the report will reflect structural validity, but NOT chain-of-trust acceptance.
- QueCloud will manage trust lists centrally; clients should prefer verifying through QueCloud for a consistent policy baseline.

Remote Manifests
- Generation:
  - `embed = false` requests no-embed mode
  - `remote_manifest_url` can be set to a distribution endpoint
- Verification:
  - `allow_remote_manifests = true` enables remote fetches per c2pa settings
  - For offline/air-gapped contexts, keep this disabled.

BMFF Fragmented Signing
- Feature-gated via `bmff`
- API: `generate_fragmented_bmff(FragmentedBmffConfig)`
- Inputs:
  - `init_glob`: path/glob to init segments
  - `fragments_glob`: glob per init directory for fragment segments
  - `output_dir`: destination tree where signed media will be written
- Requires valid MP4/ISOBMFF init and fragment segments; otherwise the C2PA library will error.

Ingredients
- `create_ingredient(IngredientConfig)` emits either:
  - Memory: JSON bytes of the ingredient
  - Path(dir): a folder with resources and `ingredient.json`

Error Model
- `EngineError` enumerates configuration, IO, JSON, C2PA, feature gating, and panic (guard) failures.
- Panics in the adapter are caught and converted to `EngineError::Panic` to keep FFI boundaries safe.