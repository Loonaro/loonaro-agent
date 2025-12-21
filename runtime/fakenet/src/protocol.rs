use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Trait for implementing new protocol handlers
#[async_trait]
pub trait Protocol: Send + Sync {
    /// Protocol name (dns, http, smtp, etc.)
    fn name(&self) -> &'static str;

    /// Start the protocol service
    async fn run(&self) -> anyhow::Result<()>;

    /// Stop the service gracefully
    async fn stop(&self) -> anyhow::Result<()>;
}

/// Trait for protocol services (implemented by DNS, HTTP, etc.)
#[async_trait]
pub trait ProtocolService: Send + Sync {
    async fn serve(&self) -> anyhow::Result<()>;
}

/// Event emitted by protocol handlers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolEvent {
    /// Unique event ID
    pub id: String,

    /// Timestamp
    pub timestamp: DateTime<Utc>,

    /// Protocol name
    pub protocol: String,

    /// Source IP/port
    pub source: String,

    /// Event type (query, request, connection, etc.)
    pub event_type: String,

    /// Protocol-specific data
    pub data: ProtocolData,

    /// Rule that matched (if any)
    pub matched_rule: Option<String>,

    /// Response that was sent
    pub response_summary: Option<String>,

    /// Tags from matched rule
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ProtocolData {
    Dns {
        domain: String,
        query_type: String,
        response_ip: Option<String>,
    },
    Http {
        method: String,
        uri: String,
        host: Option<String>,
        user_agent: Option<String>,
        content_type: Option<String>,
        body_size: usize,
        body_preview: Option<String>,
        headers: HashMap<String, String>,
    },
    Tcp {
        data_size: usize,
        data_preview: Option<String>,
    },
    Unknown {
        raw: String,
    },
}

impl ProtocolEvent {
    pub fn dns(source: &str, domain: &str, query_type: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            protocol: "dns".into(),
            source: source.to_string(),
            event_type: "query".into(),
            data: ProtocolData::Dns {
                domain: domain.to_string(),
                query_type: query_type.to_string(),
                response_ip: None,
            },
            matched_rule: None,
            response_summary: None,
            tags: Vec::new(),
        }
    }

    pub fn http(source: &str, method: &str, uri: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            protocol: "http".into(),
            source: source.to_string(),
            event_type: "request".into(),
            data: ProtocolData::Http {
                method: method.to_string(),
                uri: uri.to_string(),
                host: None,
                user_agent: None,
                content_type: None,
                body_size: 0,
                body_preview: None,
                headers: HashMap::new(),
            },
            matched_rule: None,
            response_summary: None,
            tags: Vec::new(),
        }
    }

    pub fn with_rule(mut self, rule_id: &str, tags: Vec<String>) -> Self {
        self.matched_rule = Some(rule_id.to_string());
        self.tags = tags;
        self
    }

    pub fn with_response(mut self, summary: &str) -> Self {
        self.response_summary = Some(summary.to_string());
        self
    }
}
