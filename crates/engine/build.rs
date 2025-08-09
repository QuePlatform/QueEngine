// crates/engine/build.rs
fn main() {
    let f = |n| std::env::var(format!("CARGO_FEATURE_{}", n)).is_ok();
    let enclave = f("ENCLAVE");
    let kms = f("KMS");
    let cloudhsm = f("CLOUDHSM");

    if enclave && (kms || cloudhsm) {
        panic!("feature 'enclave' cannot be combined with 'kms' or 'cloudhsm'");
    }
    if f("BMFF") && !f("C2PA") {
        panic!("feature 'bmff' requires 'c2pa'");
    }
}