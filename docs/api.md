# API Reference

Types
- SigAlg: Es256 | Es384 | Ps256 | Ed25519
- VerifyMode: Summary | Info | Detailed | Tree
- AssetRef: Path(PathBuf) | Bytes { data: Vec<u8>, ext: Option<String> }
- OutputTarget: Path(PathBuf) | Memory

Generate
- sign_c2pa(C2paConfig) -> Result<Option<Vec<u8>>>
  - Returns Some(bytes) for Memory output
  - Returns None for Path output

Verify
- verify_c2pa(C2paVerificationConfig) -> Result<VerificationResult>
  - VerificationResult:
    - report: String (human-readable summary, same shape as c2patool outputs)
    - certificates: Optional<Vec<CertInfo>>
    - status: Optional<Vec<ValidationStatus>>
    - verdict: Optional<Verdict> (Allowed | Warning | Rejected)

Ingredients
- create_ingredient(IngredientConfig) -> Result<Option<Vec<u8>>>
  - Memory => Some(bytes)
  - Path(dir) => None, writes folder + ingredient.json

BMFF (feature: bmff)
- generate_fragmented_bmff(FragmentedBmffConfig) -> Result<()>

Assumptions
- C2PA SDK’s global settings are per-process. QueEngine uses a global lock and resets to a baseline after each call that mutates settings.
- Verification trust is opt-in via `TrustPolicyConfig`. Without it, structural verification will not assert CA trust.
- When using `AssetRef::Bytes`, provide `ext` when you care about media-specific handlers (png, jpg, mp4).