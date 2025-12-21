//! Artifact collection configuration
//!
//! User-configurable rules for what artifacts to collect.

mod file;
mod memory;
mod network;
mod registry;
mod settings;

pub use file::FileCollectionConfig;
pub use memory::MemoryCollectionConfig;
pub use network::NetworkCollectionConfig;
pub use registry::RegistryCollectionConfig;
pub use settings::CollectionSettings;

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Master configuration for artifact collection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactConfig {
    pub files: FileCollectionConfig,
    pub memory: MemoryCollectionConfig,
    pub network: NetworkCollectionConfig,
    pub registry: RegistryCollectionConfig,
    pub settings: CollectionSettings,
}

impl Default for ArtifactConfig {
    fn default() -> Self {
        Self {
            files: FileCollectionConfig::default(),
            memory: MemoryCollectionConfig::default(),
            network: NetworkCollectionConfig::default(),
            registry: RegistryCollectionConfig::default(),
            settings: CollectionSettings::default(),
        }
    }
}

impl ArtifactConfig {
    // pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
    //     let content = std::fs::read_to_string(path)?;
    //     Ok(serde_json::from_str(&content)?)
    // }

    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}
