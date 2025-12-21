use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Directory to store analysis artifacts and configuration
    #[arg(
        long,
        default_value = "../box_config",
        help = "Directory to store analysis artifacts and configuration"
    )]
    output_dir: String,

    /// Unique session identifier for the analysis run
    #[arg(
        long,
        default_value = "unknown-session",
        help = "Unique session identifier for the analysis run"
    )]
    session_id: String,

    /// Port to listen on (0 for dynamic allocation)
    #[arg(
        long,
        default_value_t = 0,
        help = "Port to listen on (0 for dynamic allocation)"
    )]
    port: u16,

    /// IP address to bind the monitor to
    #[arg(
        long,
        default_value = "0.0.0.0",
        help = "IP address to bind the monitor to"
    )]
    ip: String,

    /// URL of the Moose ingestion service
    #[arg(long, help = "URL of the Moose ingestion service")]
    moose_url: Option<String>,

    /// API key for authenticating with Moose
    #[arg(long, help = "API key for authenticating with Moose")]
    moose_key: Option<String>,

    /// Analysis duration in seconds
    #[arg(long, default_value_t = 60, help = "Analysis duration in seconds")]
    duration: u64,
}

pub struct AppConfig {
    pub output_dir: String,
    pub session_id: String,
    pub bind_port: u16,
    pub bind_ip: String,
    pub moose_url: String,
    pub moose_key: String,
    pub duration: u64,
}

impl AppConfig {
    pub fn load() -> Self {
        let cli = Cli::parse();

        let moose_url = cli
            .moose_url
            .or_else(|| std::env::var("MOOSE_URL").ok())
            .unwrap_or_else(|| "http://localhost:4000".to_string());

        let moose_key = cli
            .moose_key
            .or_else(|| std::env::var("MOOSE_KEY").ok())
            .unwrap_or_else(|| "moose_secret".to_string());

        Self {
            output_dir: cli.output_dir,
            session_id: cli.session_id,
            bind_port: cli.port,
            bind_ip: cli.ip,
            moose_url,
            moose_key,
            duration: cli.duration,
        }
    }
}
