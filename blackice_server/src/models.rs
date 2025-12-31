use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct LogEntry {
    pub student_id: String,
    pub session_id: String,
    pub level: String,     // replace with proper enum with INFO, ERROR, VIOLATION etc...
    pub message: String,
    pub timestamp: i64,    // Unix Timestamp
}

#[derive(Serialize)]
pub struct GenericResponse {
    pub status: String,
    pub message: String,
}