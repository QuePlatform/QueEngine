// adapters/c2pa/engine/ingredient.rs

#[cfg(feature = "c2pa")]
use c2pa::Ingredient;

use crate::domain::error::EngineResult;
use crate::domain::types::{AssetRef, IngredientConfig, OutputTarget};
use super::super::asset_utils::asset_to_temp_path;

pub fn create_ingredient(
  config: IngredientConfig,
) -> EngineResult<Option<Vec<u8>>> {
  match &config.source {
    AssetRef::Stream { reader, content_type } => {
      let format = content_type
        .as_deref()
        .unwrap_or("application/octet-stream");
      let mut stream = reader.borrow_mut();

      match config.output {
        OutputTarget::Path(dir) => {
          std::fs::create_dir_all(&dir)?;
          // There is no from_stream_with_folder; use a temp file.
          let (temp_path, _temp_dir) = asset_to_temp_path(&config.source)?;
          let report = Ingredient::from_file_with_folder(&temp_path, &dir)?;
          std::fs::write(dir.join("ingredient.json"), report.to_string())?;
          Ok(None)
        }
        OutputTarget::Memory => {
          let ingredient = Ingredient::from_stream(format, &mut *stream)?;
          Ok(Some(ingredient.to_string().into_bytes()))
        }
      }
    }
    _ => {
      let (source_path, _temp_dir) = asset_to_temp_path(&config.source)?;
      match config.output {
        OutputTarget::Path(dir) => {
          std::fs::create_dir_all(&dir)?;
          let report = Ingredient::from_file_with_folder(&source_path, &dir)?;
          std::fs::write(dir.join("ingredient.json"), report.to_string())?;
          Ok(None)
        }
        OutputTarget::Memory => {
          let report = Ingredient::from_file(&source_path)?.to_string();
          Ok(Some(report.into_bytes()))
        }
      }
    }
  }
}