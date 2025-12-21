use crate::ProtocolEvent;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs::{self, OpenOptions};
use tokio::io::AsyncWriteExt;
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub event: ProtocolEvent,
    pub logged_at: chrono::DateTime<Utc>,
}

pub struct EventLogger {
    log_dir: Option<PathBuf>,
}

impl EventLogger {
    pub fn new(log_dir: Option<String>) -> Self {
        Self {
            log_dir: log_dir.map(PathBuf::from),
        }
    }

    pub async fn log(&self, event: &ProtocolEvent) {
        // Always log to tracing
        tracing::info!(
            protocol = %event.protocol,
            source = %event.source,
            event_type = %event.event_type,
            matched_rule = ?event.matched_rule,
            "FakeNet event"
        );

        // Write to file if configured
        if let Some(ref dir) = self.log_dir {
            if let Err(e) = self.write_to_file(dir, event).await {
                warn!("Failed to write log: {}", e);
            }
        }
    }

    async fn write_to_file(&self, dir: &PathBuf, event: &ProtocolEvent) -> anyhow::Result<()> {
        fs::create_dir_all(dir).await?;
        
        let filename = format!("fakenet_{}.jsonl", Utc::now().format("%Y-%m-%d"));
        let path = dir.join(filename);
        
        let entry = LogEntry {
            event: event.clone(),
            logged_at: Utc::now(),
        };
        
        let mut line = serde_json::to_string(&entry)?;
        line.push('\n');
        
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;
        
        file.write_all(line.as_bytes()).await?;
        
        Ok(())
    }
}
