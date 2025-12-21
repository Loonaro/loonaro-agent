use axum::{
    extract::{Multipart, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::info;
use uuid::Uuid;

use crate::providers::Submission;
use crate::state::AppState;

#[derive(Serialize)]
struct JobResponse {
    job_id: String,
    status: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    yara_matches: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    yara_severity: Option<String>,
}

pub async fn submit_job(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("file").to_string();
        let file_name = field.file_name().unwrap_or("unknown.bin").to_string();

        if name == "file" {
            let data = match field.bytes().await {
                Ok(d) => d,
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": e.to_string()})),
                    )
                        .into_response()
                }
            };

            let mut hasher = Sha256::new();

            hasher.update(&data);
            let hash = hex::encode(hasher.finalize());
            info!("Received file: {}, SHA256: {}", file_name, hash);

            let yara_result = state.yara_scanner.scan_buffer(&data, &file_name);

            let (yara_matches, yara_severity) = match yara_result {
                Ok(result) => {
                    if result.has_matches() {
                        let rules: Vec<String> = result
                            .matched_rules()
                            .iter()
                            .map(|s| s.to_string())
                            .collect();
                        let severity = result.severity().to_string();
                        info!("YARA matches: {:?}, Severity: {}", rules, severity);
                        (Some(rules), Some(severity))
                    } else {
                        info!("YARA: No matches");
                        (None, None)
                    }
                }
                Err(e) => {
                    tracing::warn!("YARA scan failed: {}", e);
                    (None, None)
                }
            };

            let job_id = Uuid::new_v4().to_string();

            let moose_url = format!("{}/ingest/JobLifecycleEvent", state.config.moose.host);

            let event = json!({
                "id": Uuid::new_v4().to_string(),
                "session_id": job_id,
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "status": "CREATED",
                "details": format!("Job received. File: {}, SHA256: {}", file_name, hash),
                "yara_matches": yara_matches,
                "yara_severity": yara_severity
            });

            match state
                .http_client
                .post(&moose_url)
                .header("x-api-key", &state.config.moose.api_key)
                .json(&event)
                .send()
                .await
            {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        tracing::error!(
                            "Failed to ingest event to Moose: Status {}",
                            resp.status()
                        );
                    } else {
                        info!("Moose Ingest Success: Job CREATED with YARA results");
                    }
                }
                Err(e) => tracing::error!("Failed to connect to Moose: {}", e),
            }

            let temp_dir = std::env::temp_dir().join("loonaro_uploads");

            if let Err(e) = tokio::fs::create_dir_all(&temp_dir).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("Failed to create temp dir: {}", e)})),
                )
                    .into_response();
            }

            let temp_path = temp_dir.join(&file_name);
            if let Err(e) = tokio::fs::write(&temp_path, &data).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("Failed to save temp file: {}", e)})),
                )
                    .into_response();
            }

            let submission = Submission {
                job_id: job_id.clone(),
                file_path: temp_path,
                file_name,
                sha256: hash,
                duration_seconds: 60,
            };

            let provider = state.provider.clone();
            let config = state.config.clone();

            tokio::spawn(async move {
                match provider.start_analysis(&submission, &config).await {
                    Ok(context) => {
                        info!(
                            "Analysis started for job {}: Agent at {}",
                            submission.job_id, context.agent_address
                        );

                        // Wait for the specified duration
                        // In production, this duration might be dynamic based on agent feedback
                        tokio::time::sleep(tokio::time::Duration::from_secs(
                            submission.duration_seconds,
                        ))
                        .await;
                        info!(
                            "Analysis finished for job: {}. Cleaning up...",
                            submission.job_id
                        );

                        if let Err(e) = provider.cleanup(&context).await {
                            tracing::error!("Failed to cleanup job {}: {}", submission.job_id, e);
                        } else {
                            info!("Cleanup successful for job {}", submission.job_id);
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to start analysis for job {}: {}",
                            submission.job_id,
                            e
                        );
                    }
                }
            });

            info!("Job accepted and forwarded to provider: {}", job_id);

            return (
                StatusCode::CREATED,
                Json(JobResponse {
                    job_id,
                    status: "queued".to_string(),
                    message: "Job submitted successfully.".to_string(),
                    yara_matches,
                    yara_severity,
                }),
            )
                .into_response();
        }
    }

    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": "No file field found"})),
    )
        .into_response()
}
