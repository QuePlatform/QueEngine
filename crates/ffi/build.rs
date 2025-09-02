fn main() {
    println!("cargo:rerun-if-changed=src/lib.rs");
    // UniFFI scaffolding is handled by the uniffi::setup_scaffolding!() macro in lib.rs
    // No additional build steps needed for inline attribute mode
}