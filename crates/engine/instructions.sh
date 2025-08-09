# build
cargo build --release

# Swift bindings
cargo run --bin uniffi-bindgen \
          --features uniffi/cli \
          generate \
          --library target/release/libque_core.dylib \
          --language swift   \
          --out-dir ./bindings/swift

# Kotlin bindings
cargo run --bin uniffi-bindgen \
          --features uniffi/cli \
          generate \
          --library target/release/libque_core.dylib \
          --language kotlin   \
          --out-dir ./bindings/kotlin

# WASM bindings
wasm-pack build --target web --out-dir bindings/js