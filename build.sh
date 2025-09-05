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

# WASM bindings - Infrastructure ready, blocked by ring crate C dependencies
# wasm-pack build crates/ffi --target web --out-dir bindings/js --no-default-features --features c2pa,wasm
# Note: Currently blocked by ring crate's C dependencies. Will work once resolved upstream.