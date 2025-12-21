mod config;
mod dns;
mod http;
mod logging;
mod protocol;
mod rules;

pub use config::{FakeNetConfig, ProtocolConfig, ResponseRule};
pub use dns::DnsService;
pub use http::HttpService;
pub use logging::{EventLogger, LogEntry};
pub use protocol::{Protocol, ProtocolEvent, ProtocolService};
pub use rules::RuleEngine;

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tracing::info;

/// Core FakeNet instance managing all protocol services
pub struct FakeNet {
    config: Arc<RwLock<FakeNetConfig>>,
    event_tx: broadcast::Sender<ProtocolEvent>,
    rule_engine: Arc<RuleEngine>,
    logger: Arc<EventLogger>,
}

impl FakeNet {
    pub fn new(config: FakeNetConfig) -> Self {
        let (event_tx, _) = broadcast::channel(10000);
        let rule_engine = Arc::new(RuleEngine::new(config.rules.clone()));
        let logger = Arc::new(EventLogger::new(config.log_directory.clone()));

        Self {
            config: Arc::new(RwLock::new(config)),
            event_tx,
            rule_engine,
            logger,
        }
    }

    pub fn with_rules(mut self, rules: Vec<ResponseRule>) -> Self {
        self.rule_engine = Arc::new(RuleEngine::new(rules));
        self
    }

    pub async fn run(&self) -> Result<()> {
        let config = self.config.read().await;
        info!(
            "Starting FakeNet with {} protocols configured",
            config.protocols.len()
        );

        let mut handles = Vec::new();

        for proto_config in &config.protocols {
            let handle = match proto_config.protocol.as_str() {
                "dns" => {
                    let service = DnsService::new(
                        proto_config.clone(),
                        self.event_tx.clone(),
                        self.rule_engine.clone(),
                    );
                    Some(tokio::spawn(async move { service.serve().await }))
                }
                "http" | "https" => {
                    let service = HttpService::new(
                        proto_config.clone(),
                        self.event_tx.clone(),
                        self.rule_engine.clone(),
                    );
                    Some(tokio::spawn(async move { service.serve().await }))
                }
                _ => {
                    tracing::warn!("Unknown protocol: {}", proto_config.protocol);
                    None
                }
            };

            if let Some(h) = handle {
                handles.push(h);
            }
        }

        // Event logging task
        let mut rx = self.event_tx.subscribe();
        let logger = self.logger.clone();
        handles.push(tokio::spawn(async move {
            while let Ok(event) = rx.recv().await {
                logger.log(&event).await;
            }
            Ok(())
        }));

        for h in handles {
            h.await??;
        }

        Ok(())
    }

    /// Subscribe to all protocol events
    pub fn subscribe(&self) -> broadcast::Receiver<ProtocolEvent> {
        self.event_tx.subscribe()
    }

    /// Hot-reload configuration
    pub async fn reload_config(&self, config: FakeNetConfig) {
        let mut cfg = self.config.write().await;
        *cfg = config;
    }

    /// Add a rule dynamically
    pub fn add_rule(&self, rule: ResponseRule) {
        self.rule_engine.add_rule(rule);
    }
}

/// Builder for FakeNet with fluent API
pub struct FakeNetBuilder {
    config: FakeNetConfig,
}

impl FakeNetBuilder {
    pub fn new() -> Self {
        Self {
            config: FakeNetConfig::default(),
        }
    }

    pub fn dns(mut self, port: u16) -> Self {
        self.config.protocols.push(ProtocolConfig {
            protocol: "dns".into(),
            port,
            enabled: true,
            options: Default::default(),
        });
        self
    }

    pub fn http(mut self, port: u16) -> Self {
        self.config.protocols.push(ProtocolConfig {
            protocol: "http".into(),
            port,
            enabled: true,
            options: Default::default(),
        });
        self
    }

    pub fn https(mut self, port: u16) -> Self {
        self.config.protocols.push(ProtocolConfig {
            protocol: "https".into(),
            port,
            enabled: true,
            options: Default::default(),
        });
        self
    }

    pub fn default_ip(mut self, ip: &str) -> Self {
        self.config.default_response_ip = ip.to_string();
        self
    }

    pub fn rule(mut self, rule: ResponseRule) -> Self {
        self.config.rules.push(rule);
        self
    }

    pub fn log_to(mut self, directory: &str) -> Self {
        self.config.log_directory = Some(directory.to_string());
        self
    }

    pub fn build(self) -> FakeNet {
        FakeNet::new(self.config)
    }
}

impl Default for FakeNetBuilder {
    fn default() -> Self {
        Self::new()
    }
}
