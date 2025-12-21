use crate::config::Config;
use crate::models::{AnalysisReport, FeatureVector};
use anyhow::{Context, Result};
use reqwest::Client;
use rhai::{Engine, Scope};
use std::fs;
use std::path::Path;

pub struct ScoringEngine {
    client: Client,
    config: Config,
}

impl ScoringEngine {
    pub fn new(config: Config) -> Self {
        Self {
            client: Client::new(),
            config,
        }
    }

    pub async fn score(&self, session_id: &str) -> Result<AnalysisReport> {
        // 1. Fetch Features from Moose View
        let url = format!("{}/consumption/FeatureVectorView?id={}", self.config.moose_api_url, session_id);
        println!("Fetching features from: {}", url);
        
        let features_vec: Vec<FeatureVector> = self.client.get(&url)
            .send()
            .await?
            .json()
            .await
            .context("Failed to fetch features from Moose")?;

        let features = features_vec.first().context("No features found for session")?.clone();

        // 2. Setup Rhai Engine
        let engine = Engine::new();
        let mut scope = Scope::new();

        // Register Features in Scope
        scope.push("features", features.clone());
        
        // Helper variables
        scope.push("score", 0_i64);
        scope.push("verdict", "Benign".to_string());
        scope.push("rules", Vec::<String>::new());

        // 3. Run Policies (Hot-Reload)
        let policies_path = Path::new(&self.config.policies_dir);
        if !policies_path.exists() {
            fs::create_dir_all(policies_path)?;
        }

        for entry in fs::read_dir(policies_path)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "rhai") {
                let script = fs::read_to_string(&path)?;
                println!("Running policy: {:?}", path.file_name().unwrap());
                
                if let Err(e) = engine.run_with_scope(&mut scope, &script) {
                    eprintln!("Error running policy {:?}: {}", path, e);
                }
            }
        }

        // 4. Extract Results
        let score: i64 = scope.get_value("score").unwrap_or(0);
        let triggered_rules: Vec<String> = scope.get_value("rules").unwrap_or_default();
        
        // Determine Verdict if not set by script
        let verdict_val: String = scope.get_value("verdict").unwrap_or_else(|| "Benign".to_string());
        let final_verdict = if score > 70 && verdict_val == "Benign" {
            "Malicious".to_string()
        } else {
            verdict_val
        };

        let report = AnalysisReport {
            session_id: session_id.to_string(),
            score,
            verdict: final_verdict,
            triggered_rules,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        // 5. Ingest Result to Moose
        self.ingest_report(&report).await?;

        Ok(report)
    }

    async fn ingest_report(&self, report: &AnalysisReport) -> Result<()> {
        let url = format!("{}/ingest/AnalysisReport", self.config.moose_api_url);
        self.client.post(&url)
            .header("x-api-key", &self.config.moose_api_key)
            .json(report)
            .send()
            .await
            .context("Failed to ingest report to Moose")?;
        Ok(())
    }
}
