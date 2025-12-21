pub mod handlers;

use axum::Router;
use axum::routing::{get, post};
use crate::state::AppState;
use crate::api::handlers::submit_job;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(|| async { "Loonaro Orchestrator Online (Modular)" }))
        .route("/submit", post(submit_job))
}
