# QueEngine

## 1. Overview

**QueEngine** is a high-level, configurable Rust library designed to be the core provenance and authenticity engine for the Que Platform. Its primary function is to provide a safe, robust, and developer-friendly interface for interacting with the C2PA (Coalition for Content Provenance and Authenticity) standard.

While the official `c2pa-rs` library is powerful, it is a low-level toolkit. QueEngine acts as an abstraction layer on top of it, providing:

- **Safe Defaults:** Common operations like signing and verifying work out-of-the-box with sensible defaults.
- **Powerful Configuration:** Exposes the full power of the underlying C2PA library through well-structured configuration objects, allowing advanced users to customize every aspect of the process.
- **Clear Boundaries:** A clean separation between pure domain logic and concrete implementation details (the "adapter" pattern).
- **Security & Stability:** Manages thread-safety for global settings and provides robust error handling to prevent panics from crossing FFI boundaries.

### 1.1. Role in the Que Ecosystem

- **QueCloud:** The managed service (`QueCloud`) uses QueEngine as a dependency to perform all its C2PA operations (signing with cloud-managed keys, verification with managed trust policies).
- **Language SDKs (FFI):** The `que-ffi` crate within this repository uses QueEngine to generate native bindings for Swift (iOS/macOS) and Kotlin (Android), enabling on-device, offline provenance operations.

### 1.2. Core Concepts

#### Domain-Adapter Architecture

The engine is split into two main concepts:

- `domain`: This module contains pure Rust types, traits, and error definitions. It has no knowledge of C2PA or any other specific implementation. It defines *what* the engine can do (e.g., `ManifestEngine` trait).
- `adapters`: This module provides the concrete implementation. The `c2pa.rs` adapter implements the `ManifestEngine` trait using the `c2pa-rs` library. This design allows for future adapters (e.g., for blockchain anchoring) to be added without changing the core domain.

#### Thread-Safe Settings Management

The underlying `c2pa-rs` library relies on a global static configuration for certain settings (like trust validation). Modifying this from multiple threads is unsafe.

**Assumption:** To solve this, QueEngine uses a global `Mutex` (`C2PA_SETTINGS_LOCK`). Any function that needs to modify these global settings (like `verify` with a custom policy) will lock the mutex, apply the settings for the duration of the call, and then restore the baseline settings before releasing the lock. This serializes all settings-dependent C2PA calls, ensuring thread safety at the cost of some parallelism for those specific operations.

#### Feature Gating

QueEngine is heavily feature-gated to produce minimal binaries for different targets. This is critical for security and performance. For example, the `enclave` feature (for on-device signing) should never be compiled into the `QueCloud` server binary, and the `kms` feature (for cloud signing) should never be compiled into a device-side library.

See the **Feature Flags** section for a complete list.

## 2. Getting Started

Add QueEngine to your project's `Cargo.toml`.

Currently, we have not figured out a way to import the github repository QueEngine because it is private. QueCloud references the repository directly since it is on the same machine

```toml
[dependencies]
que-engine = { path = "../Engine/crates/engine" }
```

**To include support for fragmented BMFF (MP4) files:**
```toml
[dependencies]
que-engine = { path = "../Engine/crates/engine", features = ["bmff"] }
```

## 3. Next Steps

- **[API Reference](./docs/API.md):** Explore the public functions available in the engine.
- **[Data Structures](./docs/TYPES.md):** Understand the configuration and result types used by the API.