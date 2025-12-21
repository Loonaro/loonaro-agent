use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FakeNetConfig {
    #[serde(default)]
    pub protocols: Vec<ProtocolConfig>,

    #[serde(default = "default_ip")]
    pub default_response_ip: String,

    #[serde(default)]
    pub rules: Vec<ResponseRule>,

    #[serde(default)]
    pub log_directory: Option<String>,

    #[serde(default)]
    pub capture_payloads: bool,

    #[serde(default = "default_max_payload")]
    pub max_payload_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolConfig {
    pub protocol: String,
    pub port: u16,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub options: HashMap<String, String>,
}

/// Rule for matching requests and generating responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseRule {
    /// Unique identifier for this rule
    pub id: String,

    /// Protocol this rule applies to (dns, http, etc.)
    pub protocol: String,

    /// Pattern to match (regex)
    pub match_pattern: String,

    /// Field to match against (domain, uri, host, user_agent, body)
    #[serde(default = "default_match_field")]
    pub match_field: String,

    /// Response action
    pub action: ResponseAction,

    /// Priority (higher = checked first)
    #[serde(default)]
    pub priority: i32,

    /// Whether to log matches
    #[serde(default = "default_true")]
    pub log_match: bool,

    /// Tags for categorization
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ResponseAction {
    /// Return a specific IP for DNS
    DnsResolve { ip: String },

    /// Return specific HTTP response
    HttpResponse {
        status: u16,
        body: String,
        #[serde(default)]
        headers: HashMap<String, String>,
    },

    /// Serve a file from disk
    ServeFile { path: String },

    /// Proxy to real destination (for selective passthrough)
    Proxy,

    /// Drop/ignore the request
    Drop,

    /// Delay response by N milliseconds
    Delay { ms: u64, then: Box<ResponseAction> },

    /// Return error
    Error { message: String },
}

fn default_ip() -> String {
    "10.0.0.1".to_string()
}
fn default_true() -> bool {
    true
}
fn default_max_payload() -> usize {
    1024 * 1024
} // 1MB
fn default_match_field() -> String {
    "any".to_string()
}

impl Default for FakeNetConfig {
    fn default() -> Self {
        Self {
            protocols: vec![
                ProtocolConfig {
                    protocol: "dns".into(),
                    port: 53,
                    enabled: true,
                    options: Default::default(),
                },
                ProtocolConfig {
                    protocol: "http".into(),
                    port: 80,
                    enabled: true,
                    options: Default::default(),
                },
            ],
            default_response_ip: "10.0.0.1".to_string(),
            rules: Vec::new(),
            log_directory: None,
            capture_payloads: true,
            max_payload_size: 1024 * 1024,
        }
    }
}

impl ResponseRule {
    /// Create a DNS rule that resolves matching domains to an IP
    pub fn dns_resolve(id: &str, pattern: &str, ip: &str) -> Self {
        Self {
            id: id.to_string(),
            protocol: "dns".into(),
            match_pattern: pattern.to_string(),
            match_field: "domain".into(),
            action: ResponseAction::DnsResolve { ip: ip.to_string() },
            priority: 0,
            log_match: true,
            tags: Vec::new(),
        }
    }

    /// Create an HTTP rule that returns a specific response
    pub fn http_response(id: &str, pattern: &str, status: u16, body: &str) -> Self {
        Self {
            id: id.to_string(),
            protocol: "http".into(),
            match_pattern: pattern.to_string(),
            match_field: "uri".into(),
            action: ResponseAction::HttpResponse {
                status,
                body: body.to_string(),
                headers: Default::default(),
            },
            priority: 0,
            log_match: true,
            tags: Vec::new(),
        }
    }

    /// Create a rule to drop matching requests
    pub fn drop(id: &str, protocol: &str, pattern: &str) -> Self {
        Self {
            id: id.to_string(),
            protocol: protocol.into(),
            match_pattern: pattern.to_string(),
            match_field: "any".into(),
            action: ResponseAction::Drop,
            priority: 100,
            log_match: true,
            tags: vec!["blocked".into()],
        }
    }

    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }
}
