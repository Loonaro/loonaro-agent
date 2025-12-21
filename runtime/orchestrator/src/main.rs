mod api;
mod config;
mod providers;
mod state;

use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::{Config, ProviderConfig};
use crate::providers::windows::WindowsSandboxProvider;
use crate::providers::AnalysisProvider;
use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "orchestrator=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // CLI: Check for schema generation
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "config" && args.get(2).map(|s| s.as_str()) == Some("--schema")
    {
        let schema = schemars::schema_for!(Config);
        println!("{}", serde_json::to_string_pretty(&schema)?);
        return Ok(());
    }

    // Initialize Provider (Dependency Injection)
    let current_dir = std::env::current_dir()?;
    let config = Config::load()?;

    // Dynamic Provider Selection
    let provider: Arc<dyn AnalysisProvider> = match &config.provider {
        ProviderConfig::Sandbox(_sandbox_config) => {
            // Resolve paths relative to CWD if relative, or use absolute
            let staging_base = current_dir.join(&config.server.staging_dir);
            let monitor_path = current_dir.join(&config.server.monitor_bin_path);

            Arc::new(WindowsSandboxProvider::new(monitor_path, staging_base))
        } // Future: HyperV(config) => Arc::new(HyperVProvider::new(config))
    };

    tracing::info!("Using Analysis Provider: {}", provider.name());

    // Initialize YARA Scanner with builtin rules
    tracing::info!("Initializing YARA scanner...");
    let yara_scanner = match yara_scanner::ScannerBuilder::new()
        .timeout(30)
        .max_file_size(50 * 1024 * 1024) // 50MB max
        .include_strings(true)
        .build()
    {
        Ok(scanner) => Arc::new(scanner),
        Err(e) => {
            tracing::error!("Failed to initialize YARA scanner: {}", e);
            return Err(e);
        }
    };
    tracing::info!("YARA scanner initialized with builtin malware detection rules");

    let state = AppState {
        provider,
        http_client: reqwest::Client::new(),
        config: config.clone(),
        yara_scanner,
    };

    let app = api::routes()
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let port = config.server.port;
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
