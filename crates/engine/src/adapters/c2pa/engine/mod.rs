// adapters/c2pa/engine/mod.rs

use crate::domain::manifest_engine::ManifestEngine;
use crate::domain::types::{
  C2paConfig, C2paVerificationConfig, IngredientConfig,
};
use crate::domain::verify::VerificationResult;
use crate::domain::error::EngineResult;

mod common;
mod sign;
mod verify;
mod ingredient;
#[cfg(feature = "bmff")]
mod bmff;

pub struct C2pa;

impl ManifestEngine for C2pa {
  type Config = C2paConfig;
  type VerificationConfig = C2paVerificationConfig;
  type Artifact = Option<Vec<u8>>;

  fn generate(cfg: Self::Config) -> EngineResult<Self::Artifact> {
    sign::sign_c2pa(cfg)
  }

  fn verify(cfg: Self::VerificationConfig) -> EngineResult<VerificationResult> {
    verify::verify_c2pa(cfg)
  }
}

impl C2pa {
  #[cfg(all(feature = "c2pa", feature = "bmff"))]
  pub fn generate_fragmented_bmff(
    cfg: crate::domain::types::FragmentedBmffConfig,
  ) -> EngineResult<()> {
    bmff::generate_fragmented_bmff(cfg)
  }

  #[cfg(feature = "c2pa")]
  pub fn create_ingredient(
    cfg: IngredientConfig,
  ) -> EngineResult<Option<Vec<u8>>> {
    ingredient::create_ingredient(cfg)
  }
}