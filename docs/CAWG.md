# CAWG (Creator Assertions Working Group) Identity Assertions

## Overview

CAWG (Creator Assertions Working Group) identity assertions provide enhanced creator verification for digital content by allowing organizations to cryptographically assert the identity of content creators within C2PA manifests.

The QueEngine implements CAWG v1 specification support, enabling X.509 certificate-based identity assertions that can be validated independently of the main manifest signature.

## Key Concepts

### Identity Assertions vs Manifest Signatures

- **Manifest Signature**: Proves authenticity and integrity of the C2PA manifest and its assertions
- **CAWG Identity Assertion**: Provides verifiable information about the content creator's identity

### Dual-Signing Architecture

When CAWG is enabled, the QueEngine creates a dual-signer setup:

1. **Main C2PA Signer**: Signs the manifest containing content assertions (actions, thumbnails, etc.)
2. **CAWG Identity Signer**: Adds a separate identity assertion referencing the main manifest

### Certificate Reuse Patterns

The QueEngine supports two certificate usage patterns:

#### UseMainSigner (Default)
Reuses the same X.509 certificate used for the main C2PA manifest:

```rust
let cawg_identity = CawgIdentity {
    signer: CawgSigner::UseMainSigner,  // Reuse main signer certs
    signing_alg: SigAlg::Ed25519,
    referenced_assertions: vec!["c2pa.actions".to_string()],
    timestamper: None,
};
```

#### Separate Certificates
Uses different certificates for CAWG identity assertions:

```rust
let cawg_signer = Signer::from_str("local:/path/cawg-cert.pem,/path/cawg-key.pem").unwrap();
let cawg_identity = CawgIdentity {
    signer: CawgSigner::Separate(cawg_signer),  // Use separate certs
    signing_alg: SigAlg::Ed25519,
    referenced_assertions: vec!["c2pa.actions".to_string()],
    timestamper: None,
};
```

## Usage Examples

### Basic CAWG Signing with Certificate Reuse

```rust
use que_engine::{sign_c2pa, C2paConfig, AssetRef, Signer, CawgIdentity, CawgSigner, SigAlg};
use std::str::FromStr;

let main_signer = Signer::from_str("env:CERT_PEM,KEY_PEM").unwrap();

// Enable CAWG with certificate reuse (default behavior)
let cawg_identity = CawgIdentity {
    signer: CawgSigner::UseMainSigner,
    signing_alg: SigAlg::Ed25519,
    referenced_assertions: vec!["c2pa.actions".to_string()],
    timestamper: None,
};

let config = C2paConfig {
    source: AssetRef::Path("image.jpg".into()),
    output: OutputTarget::Path("signed.jpg".into()),
    signer: main_signer,
    signing_alg: SigAlg::Es256,
    cawg_identity: Some(cawg_identity),
    ..Default::default()
};

sign_c2pa(config)?;
```

### CAWG Signing with Separate Certificates

```rust
use que_engine::{sign_c2pa, C2paConfig, AssetRef, Signer, CawgIdentity, CawgSigner, SigAlg};

// Main manifest signer
let main_signer = Signer::from_str("env:CERT_PEM,KEY_PEM").unwrap();

// Separate CAWG identity signer
let cawg_signer = Signer::from_str("local:/path/cawg-cert.pem,/path/cawg-key.pem").unwrap();

let cawg_identity = CawgIdentity {
    signer: CawgSigner::Separate(cawg_signer),
    signing_alg: SigAlg::Ed25519,
    referenced_assertions: vec!["c2pa.actions".to_string(), "c2pa.hash.data".to_string()],
    timestamper: Some(Timestamper::from_str("http://timestamp.digicert.com").unwrap()),
};

let config = C2paConfig {
    source: AssetRef::Path("image.jpg".into()),
    output: OutputTarget::Path("signed.jpg".into()),
    signer: main_signer,
    signing_alg: SigAlg::Es256,
    cawg_identity: Some(cawg_identity),
    ..Default::default()
};

sign_c2pa(config)?;
```

### CAWG Verification

```rust
use que_engine::{verify_c2pa, C2paVerificationConfig, AssetRef, CawgVerifyOptions};

// Configure CAWG verification
let cawg_opts = CawgVerifyOptions {
    validate: true,
    require_valid_identity: true,
};

let config = C2paVerificationConfig {
    source: AssetRef::Path("signed.jpg".into()),
    cawg: Some(cawg_opts),
    ..Default::default()
};

let result = verify_c2pa(config)?;

if let Some(cawg_verification) = result.cawg {
    println!("CAWG Identity Present: {}", cawg_verification.present);
    println!("CAWG Identity Valid: {}", cawg_verification.valid);
    if let Some(sig_info) = cawg_verification.signature_info {
        println!("Signature Info: {}", sig_info);
    }
}
```

## Security Considerations

### Certificate Management

- **Certificate Reuse**: When using `UseMainSigner`, the same certificate appears in both the main manifest signature and CAWG identity assertion
- **Separate Certificates**: Each certificate serves a distinct purpose (manifest integrity vs creator identity)
- **Private Key Protection**: Private keys are zeroized from memory immediately after signer construction
- **File Permissions**: On Unix systems, private key files must have restrictive permissions (0600 or stricter)

### Validation Behavior

- **Presence Check**: Verifies whether a CAWG identity assertion exists in the manifest
- **Validity Check**: Validates the CAWG identity assertion signature and referenced assertions
- **Reference Validation**: Ensures referenced assertions actually exist in the manifest
- **Certificate Chain**: CAWG validation includes full certificate chain verification

### Performance Implications

- **Dual Signing**: CAWG adds computational overhead for an additional signature operation
- **Validation**: CAWG validation runs as a post-validation step after standard C2PA validation
- **Memory Usage**: Temporary certificate material is immediately zeroized after use

## Integration Patterns

### News Organizations

```rust
// Same certificate for both manifest and journalist identity
let cawg_identity = CawgIdentity {
    signer: CawgSigner::UseMainSigner,  // Organization cert = journalist identity
    signing_alg: SigAlg::Ed25519,
    referenced_assertions: vec![
        "c2pa.actions".to_string(),
        "cawg.training-mining".to_string(),
    ],
    timestamper: None,
};
```

### Content Platforms

```rust
// Platform cert for manifest, separate user certs for identity
let user_cawg_signer = get_user_identity_signer(user_id);
let cawg_identity = CawgIdentity {
    signer: CawgSigner::Separate(user_cawg_signer),
    signing_alg: SigAlg::Ed25519,
    referenced_assertions: vec!["c2pa.actions".to_string()],
    timestamper: None,
};
```

### Enterprise Workflows

```rust
// Separate certificates for different security domains
let cawg_identity = CawgIdentity {
    signer: CawgSigner::Separate(enterprise_identity_signer),
    signing_alg: SigAlg::Es384,  // Higher security algorithm
    referenced_assertions: vec![
        "c2pa.actions".to_string(),
        "c2pa.hash.data".to_string(),
        "enterprise.workflow".to_string(),
    ],
    timestamper: Some(enterprise_timestamper),
};
```

## Configuration Options

### CawgIdentity Fields

| Field | Type | Description |
|-------|------|-------------|
| `signer` | `CawgSigner` | Certificate source (main signer reuse or separate) |
| `signing_alg` | `SigAlg` | Algorithm for CAWG signature (Ed25519 recommended) |
| `referenced_assertions` | `Vec<String>` | Assertion labels this identity references |
| `timestamper` | `Option<Timestamper>` | Optional timestamp authority for CAWG signature |

### CawgVerifyOptions Fields

| Field | Type | Description |
|-------|------|-------------|
| `validate` | `bool` | Whether to perform CAWG validation |
| `require_valid_identity` | `bool` | Whether to fail verification if CAWG identity is missing/invalid |

## Supported Algorithms

- **Ed25519** (recommended): Best performance, good security, compact signatures
- **ES256**: Compatible with most X.509 certificate authorities
- **ES384**: Higher security with larger signatures

## Error Handling

### Common Errors

- **Feature Not Enabled**: `cawg` feature must be enabled at compile time
- **Certificate Permissions**: Private key files must have restrictive permissions
- **Referenced Assertions Missing**: CAWG identity references assertions that don't exist
- **Invalid Claim Version**: CAWG requires C2PA claim version 2

### Error Codes

CAWG validation can produce specific error codes:
- `cawg.identity.sig_type.unknown`: Unsupported signature type
- `cawg.identity.cbor.invalid`: Malformed CAWG assertion data
- `cawg.identity.assertion.mismatch`: Assertion hash mismatch
- `cawg.identity.hard_binding_missing`: Missing hard binding reference

## Troubleshooting

### CAWG Validation Fails

1. **Check Feature Flag**: Ensure `cawg` feature is enabled
2. **Verify Certificates**: Confirm certificates are valid and properly formatted
3. **Check Permissions**: Ensure private key files have correct permissions (Unix)
4. **Validate References**: Ensure referenced assertions exist in the manifest

### Performance Issues

1. **Certificate Reuse**: Use `UseMainSigner` to avoid duplicate certificate loading
2. **Algorithm Selection**: Ed25519 is faster than ECDSA algorithms
3. **Timestamp Authority**: Only use timestamping when required

### Integration Issues

1. **Claim Version**: CAWG automatically enforces claim version 2
2. **Manifest Structure**: CAWG assertions are added alongside standard C2PA assertions
3. **Validation Order**: Standard C2PA validation runs before CAWG validation

## Best Practices

### Security

- Use certificate reuse (`UseMainSigner`) when the same entity signs both manifest and identity
- Use separate certificates when different entities handle manifest signing vs identity assertion
- Always use restrictive file permissions for private keys
- Consider using hardware security modules (HSM) for production deployments

### Performance

- Prefer Ed25519 for CAWG signatures when possible
- Reuse certificates when appropriate to reduce overhead
- Only timestamp CAWG signatures when legally required

### Compatibility

- CAWG requires C2PA claim version 2 (automatically enforced)
- All major C2PA validators support CAWG identity assertions
- The feature is fully backward compatible when disabled

## See Also

- [API Reference](api.md) - Detailed function documentation
- [Data Types](TYPES.md) - Complete type definitions
- [C2PA Specification](https://c2pa.org/specifications/) - Official C2PA standards
- [CAWG Specification](https://cawg.io/) - Creator Assertions Working Group standards
