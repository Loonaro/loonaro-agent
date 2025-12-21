//! Artifact collection module
//!
//! Provides configurable artifact collection for malware analysis.

mod collector;
pub mod config;
mod types;

pub use collector::ArtifactCollector;

// pub use types::{Artifact, ArtifactSummary, CollectionStats, FileEvent};
