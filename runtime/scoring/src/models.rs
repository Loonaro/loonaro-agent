use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct ScoreRequest {
    pub session_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AnalysisReport {
    pub session_id: String,
    pub score: i64,
    pub verdict: String,
    pub triggered_rules: Vec<String>,
    pub timestamp: String,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct FeatureVector {
    pub session_id: String,
    #[serde(default)]
    pub total_events: i64,
    #[serde(default)]
    pub file_creates: i64,
    #[serde(default)]
    pub file_writes: i64,
    #[serde(default)]
    pub process_creates: i64,
    #[serde(default)]
    pub network_conns: i64,
    #[serde(default)]
    pub dns_queries: i64,
    #[serde(default)]
    pub unique_processes: i64,
    #[serde(default)]
    pub max_severity: i64,
    #[serde(default)]
    pub downloader_flow: bool,
}
