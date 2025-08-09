# Swift
cargo run --bin uniffi-bindgen generate \
  --library target/release/libque_engine_ffi.dylib \
  --language swift \
  --out-dir bindings/swift

# Kotlin
cargo run --bin uniffi-bindgen generate \
  --library target/release/libque_engine_ffi.dylib \
  --language kotlin \
  --out-dir bindings/kotlin