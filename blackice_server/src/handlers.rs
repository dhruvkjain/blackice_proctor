use axum::{
    extract::State,
    Json,
    http::StatusCode,
    response::IntoResponse,
};
use mongodb::bson::{doc, DateTime};
use std::sync::Arc;
use crate::{models::{LogEntry, GenericResponse}, db::AppState};

pub async fn health_checker() -> impl IntoResponse {
    const MESSAGE: &str = "BlackIce Server is running";
    let json_response = serde_json::json!({
        "status": "success",
        "message": MESSAGE
    });
    Json(json_response)
}

pub async fn ingest_logs(
    State(state): State<Arc<AppState>>,
    Json(logs): Json<Vec<LogEntry>>,
) -> impl IntoResponse {
    if logs.is_empty() {
        return (StatusCode::OK, Json(GenericResponse {
            status: "success".to_string(),
            message: "Empty batch received".to_string(),
        }));
    }

    let collection = state.db.collection::<mongodb::bson::Document>("exam_logs");
    let log_count = logs.len();

    // mapping the incoming request structs to bson docs as this
    // dynamically adds 'timestamp_iso' field to our time-series database 
    let docs: Vec<mongodb::bson::Document> = logs.into_iter().map(|log| {
        // convert UNIX timestamp (seconds) to bson DateTime (milliseconds)
        let bson_datetime = DateTime::from_millis(log.timestamp * 1000);

        doc! {
            "student_id": log.student_id,
            "session_id": log.session_id,
            "level": log.level,
            "message": log.message,
            "timestamp_iso": bson_datetime,
            "original_ts": log.timestamp    // here we are keeping the original for reference
        }
    }).collect();

    // async BULK insert
    match collection.insert_many(docs, None).await {
        Ok(_) => {
            tracing::info!("[server] ingested {} logs", log_count);
            (StatusCode::CREATED, Json(GenericResponse {
                status: "success".to_string(),
                message: format!("[server] 'ingested {} logs", log_count),
            }))
        }
        Err(e) => {
            tracing::error!("[server] failed to insert logs: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(GenericResponse {
                status: "error".to_string(),
                message: format!("[server] [db] database write failed: {}", e),
            }))
        }
    }
}
