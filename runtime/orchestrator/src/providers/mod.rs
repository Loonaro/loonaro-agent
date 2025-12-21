use anyhow::Result;
use async_trait::async_trait;
use std::any::Any;
use std::path::PathBuf;

use crate::config::Config;

#[derive(Debug, Clone)]
pub struct Submission {
    pub job_id: String,
    pub file_path: PathBuf,
    pub file_name: String,
    #[allow(dead_code)]
    pub sha256: String,
    pub duration_seconds: u64,
}

#[derive(Debug)]
pub struct AnalysisContext {
    pub instance_id: String,
    pub agent_address: String,
    pub handle: Box<dyn Any + Send + Sync>,
}

#[async_trait]
pub trait AnalysisProvider: Send + Sync {
    /// Name of the provider
    fn name(&self) -> &str;

    /// Prepare the environment and return connection details
    async fn start_analysis(
        &self,
        submission: &Submission,
        config: &Config,
    ) -> Result<AnalysisContext>;

    /// Cleanup resources
    async fn cleanup(&self, context: &AnalysisContext) -> Result<()>;
}

pub mod windows;
// pub mod hyperv; // To be implemented later
