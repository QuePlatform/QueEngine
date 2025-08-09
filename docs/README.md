# Que Engine (que-engine)

An engine providing a configurable, opinionated adapter over the C2PA SDK.
- Goal: make secure provenance “easy by default” while allowing full control.
- Separation of concerns: cloud trust, KMS/HSM orchestration, and policy rollout live in QueCloud. QueEngine focuses on asset processing, manifest generation, and verification primitives.

This repo includes:
- Rust library (que-engine)
- Optional FFI crate for Swift/Kotlin (bindings generated in /bindings by your CI)