# FFI Notes (Swift/Kotlin)

- FFI bindings are generated in `crates/ffi` and emitted to `/bindings` by CI.
- The FFI surface should expose only byte-oriented APIs:
  - sign(bytes, options) -> bytes
  - verify(bytes, options) -> JSON string/report
  - createIngredient(bytes|path, options) -> bytes|folder
- Panics are caught and mapped to error codes/messages before crossing the FFI boundary.
- Device builds must enable `enclave` feature and must NOT compile `kms`/`cloudhsm`.