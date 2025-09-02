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

# WASM bindings - Ready but requires WASM-compatible crypto
# wasm-pack build crates/ffi --target web --out-dir bindings/js
#
# Note: Currently blocked by OpenSSL dependency in the c2pa crate