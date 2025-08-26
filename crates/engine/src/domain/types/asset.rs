use std::path::PathBuf;
use std::cell::RefCell;
use std::io::{Read, Seek};

// Trait alias for streaming readers
pub trait StreamReader: Read + Seek + Send {}

impl<T: Read + Seek + Send> StreamReader for T {}

/// A reference to an asset, which can be a path, in-memory bytes, or a stream.
///
/// ## Memory Considerations
/// - `Path`: Best for local file operations. No memory overhead.
/// - `Bytes`: Suitable for small files (< 10MB) or when you need the entire file in memory.
/// - `Stream`: Recommended for large files or API scenarios to avoid memory pressure.
///   The stream must implement `Read + Seek + Send` (or just `Read + Seek` on WASM targets).
///
/// ## Production Recommendations
/// - **Bytes**: Use for files < 128MB. Avoid for API uploads > 10MB.
/// - **Stream**: Use for files > 10MB. Always provide `content_type` when possible.
/// - **Path**: Use for local files or after secure URL fetching (see URL handling below).
///
/// ## URL Handling (API Layer)
/// For remote assets, fetch to temp file first with these policies:
/// - HTTPS only by default
/// - HEAD request first; enforce max Content-Length (< 1GB)
/// - No redirects or limited redirects with re-validation
/// - Connect/read timeouts (< 5 minutes)
/// - Allow only specific MIME types you support
/// - DNS re-resolution with IP verification
/// After fetching, use AssetRef::Path for processing.
pub enum AssetRef {
    Path(PathBuf),
    Bytes {
        data: Vec<u8>,
    },
    Stream {
        /// The streaming reader. Must implement Read + Seek + Send (or Read + Seek on WASM)
        /// Wrapped in RefCell for interior mutability
        reader: RefCell<Box<dyn StreamReader>>,
        /// Optional MIME type hint (e.g., "image/jpeg", "video/mp4")
        /// If None, the engine will attempt to detect from stream content
        content_type: Option<String>,
    },
}

impl std::fmt::Debug for AssetRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssetRef::Path(path) => f.debug_tuple("Path").field(path).finish(),
            AssetRef::Bytes { data } => f.debug_struct("Bytes")
                .field("data_len", &data.len())
                .finish(),
            AssetRef::Stream { reader: _, content_type } => f.debug_struct("Stream")
                .field("content_type", content_type)
                .finish(),
        }
    }
}
