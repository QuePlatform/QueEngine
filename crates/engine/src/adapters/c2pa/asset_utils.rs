use crate::domain::error::{EngineError, EngineResult};
use crate::domain::types::{AssetRef, LimitsConfig};
use super::content_detection::{detect_extension_from_bytes, extension_to_mime_type};

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
  limits: LimitsConfig,
) -> EngineResult<(std::path::PathBuf, Option<tempfile::TempDir>)> {
  match asset {
    AssetRef::Path(p) => Ok((p.clone(), None)),
    AssetRef::Bytes { data } => {
      if data.len() > limits.max_in_memory_asset_size {
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

      // Determine filename based on content type hint or by sniffing the stream header
      let filename = if let Some(ct) = content_type {
        match ct.as_str() {
          "image/jpeg" => "asset.jpg".to_string(),
          "image/png" => "asset.png".to_string(),
          "image/gif" => "asset.gif".to_string(),
          "image/webp" => "asset.webp".to_string(),
          "video/mp4" => "asset.mp4".to_string(),
          "audio/mpeg" => "asset.mp3".to_string(),
          "application/pdf" => "asset.pdf".to_string(),
          _ => "asset".to_string(),
        }
      } else {
        // Sniff a few bytes to infer an extension when no content type is provided
        let mut maybe_ext: Option<String> = None;
        {
          use std::io::{Read, Seek, SeekFrom};
          let mut reader_ref = reader.borrow_mut();
          let mut head = [0u8; 512];
          let n = reader_ref.read(&mut head).unwrap_or(0);
          let _ = reader_ref.seek(SeekFrom::Start(0));
          if n > 0 {
            if let Some(ext) = detect_extension_from_bytes(&head[..n]) {
              maybe_ext = Some(ext.to_string());
            }
          }
        }
        if let Some(ext) = maybe_ext { format!("asset.{ext}") } else { "asset".to_string() }
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
      // Note: max_stream_read_timeout_secs is currently not enforced at this layer.
      // It is included in LimitsConfig for future extension and parity with defaults.
      let _bytes_copied = copy_with_limits(&mut *reader_ref, &mut file, limits.max_stream_copy_size)?;
      Ok((path, Some(dir)))
    }
  }
}

/// Peek the first bytes from a Read+Seek stream and infer a MIME type.
/// The stream position is restored to the start before returning.
pub fn sniff_content_type_from_reader<R: std::io::Read + std::io::Seek>(reader: &mut R) -> Option<&'static str> {
  use std::io::{SeekFrom};
  let mut head = [0u8; 512];
  let n = reader.read(&mut head).ok()?;
  let _ = reader.seek(SeekFrom::Start(0));
  if n == 0 { return None; }
  let ext = detect_extension_from_bytes(&head[..n])?;
  Some(extension_to_mime_type(ext))
}
