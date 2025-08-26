// Production-tuned memory limits to prevent memory exhaustion
pub const MAX_IN_MEMORY_ASSET_SIZE: usize = 128 * 1024 * 1024; // 128 MB - suitable for most images/videos
pub const MAX_IN_MEMORY_OUTPUT_SIZE: usize = 128 * 1024 * 1024; // 128 MB - prevents memory explosion from large signed assets

// Streaming protection limits
pub const MAX_STREAM_COPY_SIZE: usize = 1024 * 1024 * 1024; // 1 GB max for stream-to-temp-file operations
pub const MAX_STREAM_READ_TIMEOUT_SECS: u64 = 300; // 5 minutes max for stream operations

pub static C2PA_SETTINGS_LOCK: once_cell::sync::Lazy<std::sync::Mutex<()>> = once_cell::sync::Lazy::new(|| std::sync::Mutex::new(()));
pub static BASE_SETTINGS: &str = r#"{}"#;
