#[derive(Debug, Clone)]
pub enum AssetRef<'a> {
    Path(PathBuf),
    Bytes(&'a [u8]),
}

#[derive(Debug, Clone)]
pub enum OutputTarget<'a> {
    Path(PathBuf),
    Memory,                // return Vec<u8> from adapter
    Callback(&'a mut Vec<u8>), // optional for streaming in future
}