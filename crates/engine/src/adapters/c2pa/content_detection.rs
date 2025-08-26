pub fn detect_extension_from_bytes(data: &[u8]) -> Option<&'static str> {
  // JPEG
  if data.len() >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
    return Some("jpg");
  }

  // PNG
  if data.len() >= 8 && data[..8] == [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A] {
    return Some("png");
  }

  // GIF
  if data.len() >= 6 && (&data[..6] == b"GIF87a" || &data[..6] == b"GIF89a") {
    return Some("gif");
  }

  // WebP
  if data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WEBP" {
    return Some("webp");
  }

  // WAV
  if data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WAVE" {
    return Some("wav");
  }

  // AVI
  if data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"AVI " {
    return Some("avi");
  }

  // TIFF
  if data.len() >= 4 && ((&data[..4] == b"II*\0") || (&data[..4] == b"MM\0*")) {
    return Some("tiff");
  }

  // MP4/MOV/ISO-BMFF (ftyp box) - check for supported brands
  if data.len() >= 12 && &data[4..8] == b"ftyp" {
    if data.len() >= 16 {
      let brand = &data[8..12];
      // HEIC/HEIF
      if brand == b"heic" {
        return Some("heic");
      }
      if brand == b"heif" {
        return Some("heif");
      }
      // AVIF
      if brand == b"avif" {
        return Some("avif");
      }
      // MP4 variants
      if brand == b"mp42" || brand == b"isom" || brand == b"mp41" || brand == b"dash" {
        return Some("mp4");
      }
      // MOV/QuickTime
      if brand == b"qt  " {
        return Some("mov");
      }
      // M4A (audio MP4)
      if brand == b"M4A " || brand == b"m4af" {
        return Some("m4a");
      }
    }
    // Default to mp4 for unknown ftyp
    return Some("mp4");
  }

  // PDF
  if data.len() >= 5 && &data[..5] == b"%PDF-" {
    return Some("pdf");
  }

  // SVG
  if data.len() >= 5 && data[0] == b'<' {
    let head = &data[..std::cmp::min(512, data.len())];
    if let Ok(s) = std::str::from_utf8(head) {
      if s.to_ascii_lowercase().contains("<svg") {
        return Some("svg");
      }
    }
  }

  // MP3
  if data.len() >= 3 && &data[..3] == b"ID3" {
    return Some("mp3");
  }
  if data.len() >= 2 && data[0] == 0xFF && (data[1] & 0xE0) == 0xE0 {
    return Some("mp3");
  }

  None
}

/// Convert file extension to MIME type
/// This is used when we need MIME types but only have file extensions
pub fn extension_to_mime_type(extension: &str) -> &'static str {
  match extension {
    "jpg" | "jpeg" => "image/jpeg",
    "png" => "image/png",
    "gif" => "image/gif",
    "webp" => "image/webp",
    "wav" => "audio/wav",
    "avi" => "video/msvideo",
    "tiff" | "tif" => "image/tiff",
    "heic" => "image/heic",
    "heif" => "image/heif",
    "avif" => "image/avif",
    "mp4" => "video/mp4",
    "mov" => "video/quicktime",
    "m4a" => "audio/mp4",
    "mp3" => "audio/mpeg",
    "pdf" => "application/pdf",
    "svg" => "image/svg+xml",
    _ => "application/octet-stream",
  }
}
