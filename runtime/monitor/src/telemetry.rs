use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

#[derive(Serialize)]
pub struct MalwareEvent {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub session_id: String,
    pub process_name: String,
    pub pid: u32,
    pub ppid: u32,
    pub action: String,
    pub target_path: Option<String>,
    pub command_line: Option<String>,
    pub hashes: Option<Vec<String>>,
    pub user_sid: Option<String>,
    pub severity: u32,
}

impl MalwareEvent {
    pub fn new(
        session_id: &str,
        process_name: String,
        pid: u32,
        ppid: u32,
        action: &str,
        target_path: Option<String>,
        command_line: Option<String>,
        severity: u32,
    ) -> Self {
        Self {
            event_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            session_id: session_id.to_string(),
            process_name,
            pid,
            ppid,
            action: action.to_string(),
            target_path,
            command_line,
            hashes: None,
            user_sid: None,
            severity,
        }
    }
}

pub async fn send_telemetry(base_url: &str, api_key: &str, event: &MalwareEvent) {
    let client = reqwest::Client::new();
    let url = format!("{}/ingest/MalwareEvent", base_url);
    match client
        .post(&url)
        .header("x-api-key", api_key)
        .json(event)
        .send()
        .await
    {
        Ok(resp) => {
            if !resp.status().is_success() {
                eprintln!("Failed to send telemetry: {}", resp.status());
            }
        }
        Err(e) => eprintln!("Failed to send telemetry: {}", e),
    }
}

pub async fn send_lifecycle(
    base_url: &str,
    api_key: &str,
    session_id: &str,
    status: &str,
    details: &str,
) {
    let client = reqwest::Client::new();
    let url = format!("{}/ingest/JobLifecycleEvent", base_url);
    let event_id = Uuid::new_v4().to_string();

    let payload = serde_json::json!({
        "id": event_id,
        "session_id": session_id,
        "timestamp": Utc::now().to_rfc3339(),
        "status": status,
        "details": details
    });

    match client
        .post(&url)
        .header("x-api-key", api_key)
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) => {
            if !resp.status().is_success() {
                eprintln!("Failed to send lifecycle event: {}", resp.status());
            } else {
                println!("Reported Job Status: {}", status);
            }
        }
        Err(e) => eprintln!("Failed to send lifecycle event: {}", e),
    }
}
