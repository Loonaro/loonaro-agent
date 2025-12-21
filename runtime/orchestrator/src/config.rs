use anyhow::{Context, Result};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Config {
    pub server: ServerConfig,
    pub provider: ProviderConfig,
    pub moose: MooseConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ServerConfig {
    /// Port to listen on
    pub port: u16,
    /// Directory for staging intermediate artifacts
    pub staging_dir: String,
    /// Path to the monitor binary
    pub monitor_bin_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MooseConfig {
    /// URL of the Moose ingestion service
    pub host: String,
    /// API key for authenticating with Moose
    pub api_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type")]
pub enum ProviderConfig {
    #[serde(rename = "sandbox")]
    Sandbox(SandboxConfig),
    // #[serde(rename = "hyperv")]
    // HyperV(HyperVConfig),
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SandboxConfig {
    /// Optional path to .wsb config template
    pub ws_config_path: Option<String>,
}

impl Config {
    pub fn load() -> Result<Self> {
        // Try loading from orchestrator.toml using standard logic
        let config_path =
            env::var("ORCHESTRATOR_CONFIG").unwrap_or_else(|_| "orchestrator.toml".to_string());

        if Path::new(&config_path).exists() {
            let content = fs::read_to_string(&config_path).context("Failed to read config file")?;
            let config: Config = toml::from_str(&content).context("Failed to parse TOML config")?;
            Ok(config)
        } else {
            // Fallback to Env Vars for backward compatibility / dev convenience
            Self::from_env()
        }
    }

    pub fn from_env() -> Result<Self> {
        dotenv::dotenv().ok();

        let port = env::var("PORT")
            .unwrap_or_else(|_| "5000".to_string())
            .parse()
            .context("Invalid PORT")?;

        let monitor_bin_path = env::var("MONITOR_BIN_PATH")
            .unwrap_or_else(|_| "../monitor/target/debug/monitor.exe".to_string());

        let staging_dir = env::var("STAGING_DIR").unwrap_or_else(|_| "./staging".to_string());

        let moose_host =
            env::var("MOOSE_HOST").unwrap_or_else(|_| "http://localhost:4000".to_string());
        let api_key =
            env::var("MOOSE_INGEST_API_KEY").unwrap_or_else(|_| "moose_secret".to_string());

        Ok(Config {
            server: ServerConfig {
                port,
                staging_dir,
                monitor_bin_path,
            },
            provider: ProviderConfig::Sandbox(SandboxConfig {
                ws_config_path: None,
            }),
            moose: MooseConfig {
                host: moose_host,
                api_key,
            },
        })
    }
}
