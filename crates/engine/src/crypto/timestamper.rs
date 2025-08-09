//! Timestamper abstraction.

use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TimestamperError {
    #[error(
        "Invalid timestamper scheme: expected 'digicert' or 'custom:http://...'"
    )]
    InvalidScheme,
}

/// Source for a cryptographic timestamp.
#[derive(Debug, Clone)]
pub enum Timestamper {
    Digicert,
    Custom(String),
}

impl FromStr for Timestamper {
    type Err = TimestamperError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "digicert" {
            Ok(Timestamper::Digicert)
        } else if let Some(url) = s.strip_prefix("custom:") {
            Ok(Timestamper::Custom(url.to_string()))
        } else {
            Err(TimestamperError::InvalidScheme)
        }
    }
}

impl Timestamper {
    pub fn resolve(&self) -> Option<String> {
        match self {
            Timestamper::Digicert => {
                Some("http://timestamp.digicert.com".to_string())
            }
            Timestamper::Custom(url) => Some(url.clone()),
        }
    }
}