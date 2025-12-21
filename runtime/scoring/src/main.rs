pub mod config;
pub mod engine;
pub mod models;

use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use crate::config::Config;
use crate::engine::ScoringEngine;

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<ScoringEngine>,
    pub config: Config,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    
    let config = Config::from_env();
    let engine = Arc::new(ScoringEngine::new(config.clone()));
    
    let state = AppState {
        engine,
        config: config.clone(),
    };

    let app = Router::new()
        .route("/health", get(|| async { "Scoring Service Online" }))
        .route("/score", post(score_session))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    tracing::info!("Scoring Service listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn score_session(
    State(state): State<AppState>,
    Json(payload): Json<models::ScoreRequest>,
) -> impl IntoResponse {
    match state.engine.score(&payload.session_id).await {
        Ok(report) => (StatusCode::OK, Json(report)).into_response(),
        Err(e) => {
            tracing::error!("Scoring failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response()
        }
    }
}
