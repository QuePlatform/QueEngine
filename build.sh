# Build release version
cargo build --release

# Swift
cargo run -p que-engine-ffi --bin uniffi-bindgen generate \
  --library target/release/libque_engine_ffi.dylib \
  --language swift \
  --out-dir bindings/swift

# Kotlin
cargo run -p que-engine-ffi --bin uniffi-bindgen generate \
  --library target/release/libque_engine_ffi.dylib \
  --language kotlin \
  --out-dir bindings/kotlin

# WASM bindings - Commented out due to OpenSSL dependency issues
# wasm-pack build crates/ffi --target web --out-dir bindings/js
# Note: The engine uses OpenSSL which doesn't easily compile to WASM
# For WASM support, we would need to use a WASM-compatible crypto library