use crate::domain::error::{EngineError, EngineResult};
use crate::domain::types::AssetRef;
use super::constants::{MAX_IN_MEMORY_ASSET_SIZE, MAX_STREAM_COPY_SIZE};
use super::content_detection::detect_extension_from_bytes;

/// Copy data from reader to writer with size limits to prevent memory exhaustion
pub fn copy_with_limits<R: std::io::Read, W: std::io::Write>(
  reader: &mut R,
  writer: &mut W,
  max_bytes: usize,
) -> EngineResult<u64> {
  let mut buffer = [0u8; 8192]; // 8KB chunks for efficient copying
  let mut total_bytes = 0u64;

  loop {
    let bytes_read = reader.read(&mut buffer)
      .map_err(|e| EngineError::Io(e))?;

    if bytes_read == 0 {
      break; // EOF reached
    }

    // Check if this chunk would exceed the limit
    let new_total = total_bytes as usize + bytes_read;
    if new_total > max_bytes {
      return Err(EngineError::Config(
        format!("Stream size limit exceeded: {} bytes (max: {})", new_total, max_bytes)
      ));
    }

    writer.write_all(&buffer[..bytes_read])
      .map_err(|e| EngineError::Io(e))?;

    total_bytes = new_total as u64;
  }

  writer.flush().map_err(|e| EngineError::Io(e))?;
  Ok(total_bytes)
}

pub fn asset_to_temp_path(
  asset: &AssetRef,
) -> EngineResult<(std::path::PathBuf, Option<tempfile::TempDir>)> {
  match asset {
    AssetRef::Path(p) => Ok((p.clone(), None)),
    AssetRef::Bytes { data } => {
      if data.len() > MAX_IN_MEMORY_ASSET_SIZE {
        return Err(EngineError::Config("in-memory asset too large".into()));
      }
      let dir = tempfile::tempdir()?;
      let filename = if let Some(ext) = detect_extension_from_bytes(data) {
        format!("asset.{ext}")
      } else {
        "asset".to_string()
      };
      let path = dir.path().join(filename);
      std::fs::write(&path, data)?;
      Ok((path, Some(dir)))
    }
    AssetRef::Stream { reader, content_type } => {
      let dir = tempfile::tempdir()?;

      // Determine filename based on content type hint or detection
      let filename = if let Some(ct) = content_type {
        // Convert MIME type to extension
        match ct.as_str() {
          "image/jpeg" => "asset.jpg".to_string(),
          "image/png" => "asset.png".to_string(),
          "image/gif" => "asset.gif".to_string(),
          "image/webp" => "asset.webp".to_string(),
          "video/mp4" => "asset.mp4".to_string(),
          "audio/mpeg" => "asset.mp3".to_string(),
          "application/pdf" => "asset.pdf".to_string(),
          _ => "asset".to_string(), // Unknown MIME type, use generic name
        }
      } else {
        // No content type hint, use generic name and let c2pa handle it
        "asset".to_string()
      };

      let path = dir.path().join(filename);

      // For streams, we need to copy the entire stream to a temp file
      // This is still more memory-efficient than Bytes for large files because:
      // 1. The stream can be processed in chunks (64KB at a time by default)
      // 2. The temp file is on disk, not in RAM
      // 3. The original stream can be dropped after copying
      let mut file = std::fs::File::create(&path)?;

      // Borrow mutably from the RefCell and copy with protection limits
      let mut reader_ref = reader.borrow_mut();
      let _bytes_copied = copy_with_limits(&mut *reader_ref, &mut file, MAX_STREAM_COPY_SIZE)?;
      Ok((path, Some(dir)))
    }
  }
}
