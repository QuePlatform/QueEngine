// Main C2PA adapter module - re-exports all public interfaces

mod constants;
mod content_detection;
mod url_validation;
mod asset_utils;
mod settings;

#[cfg(feature = "cawg")]
mod cawg;

pub mod engine;

pub use engine::C2pa;