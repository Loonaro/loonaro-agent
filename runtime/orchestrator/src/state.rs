use crate::providers::AnalysisProvider;
use std::sync::Arc;
use yara_scanner::Scanner as YaraScanner;

#[derive(Clone)]
pub struct AppState {
    pub provider: Arc<dyn AnalysisProvider>,
    pub http_client: reqwest::Client,
    pub config: crate::config::Config,
    pub yara_scanner: Arc<YaraScanner>,
}
