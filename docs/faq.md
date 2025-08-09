# FAQ

Q: Where do “opinions” live?
A: In QueCloud. The engine is configurable with safe defaults. QueCloud provides trust lists, policy profiles, and enforcement, so you can change policy without re-shipping clients.

Q: How do I make verification trusted?
A: Provide a `TrustPolicyConfig` with anchors and optional allowed list/EKUs, or call the QueCloud verify API that injects the centrally managed trust baseline.

Q: Can I work entirely with bytes?
A: Yes. Use `AssetRef::Bytes` with `ext` when you want format-aware behavior, and `OutputTarget::Memory` for an in-memory round trip.