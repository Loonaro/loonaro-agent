//! General collection settings

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionSettings {
    pub max_total_size_mb: u64,
    pub collect_on_error: bool,
    pub hash_all_artifacts: bool,
    pub enable_yara_scan: bool,
}

impl Default for CollectionSettings {
    fn default() -> Self {
        Self {
            max_total_size_mb: 500,
            collect_on_error: true,
            hash_all_artifacts: true,
            enable_yara_scan: true,
        }
    }
}
