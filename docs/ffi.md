# FFI Notes (Swift/Kotlin)

- FFI bindings are generated in `crates/ffi` and emitted to `/bindings` by CI.
- The FFI surface should expose only byte-oriented APIs:
  - sign(bytes, options) -> bytes
  - verify(bytes, options) -> JSON string/report
  - createIngredient(bytes|path, options) -> bytes|folder
- Panics are caught and mapped to error codes/messages before crossing the FFI boundary.
- Device builds must enable `enclave` feature and must NOT compile `kms`/`cloudhsm`.

## Security and configuration notes

- BYO certs/keys only. No test/bundled PEMs are shipped. Provide cert/key via:
  - local file paths, or
  - environment variables containing PEMs.
- Remote manifest fetching is disabled by default. If needed, build with `remote_manifests` and opt-in at runtime.
- HTTP URLs are disabled by default. If absolutely required, build with `http_urls` and set the per-call flag; HTTPS is strongly recommended.
- CAWG (Creator Assertions Working Group) identity assertions are available when built with the `cawg` feature flag.
- URL validation includes DNS/IP checks to block private/loopback/link-local ranges.