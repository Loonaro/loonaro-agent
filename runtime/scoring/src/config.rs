use dotenv::dotenv;
use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub moose_api_url: String, // http://localhost:4000
    pub moose_api_key: String,
    pub policies_dir: String,
    pub port: u16,
}

impl Config {
    pub fn from_env() -> Self {
        dotenv().ok();

        let moose_host =
            env::var("MOOSE_HOST").unwrap_or_else(|_| "http://localhost:4000".to_string());

        let moose_api_key =
            env::var("MOOSE_INGEST_API_KEY").unwrap_or_else(|_| "moose_secret".to_string());

        let policies_dir = env::var("POLICIES_DIR").unwrap_or_else(|_| "./policies".to_string());

        let port = env::var("SCORING_PORT")
            .unwrap_or_else(|_| "5002".to_string())
            .parse()
            .unwrap();

        Config {
            moose_api_url: moose_host,
            moose_api_key,
            policies_dir,
            port,
        }
    }
}
