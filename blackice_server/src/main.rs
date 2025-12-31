mod db;
mod handlers;
mod models;

use axum::{routing::{get, post}, Router};
use std::sync::Arc;
use dotenv::dotenv;
use std::net::SocketAddr;
use tower_http::cors::CorsLayer;

#[tokio::main]
async fn main() {
    dotenv().ok();
    
    // initialize logging tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // initialize mongodb
    let state = match db::init_db().await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("[error] failed to connect to database: {}", e);
            std::process::exit(1);
        }
    };

    // routes
    let app = Router::new()
        .route("/health", get(handlers::health_checker))
        .route("/api/logs", post(handlers::ingest_logs))
        // allow client to talk to server (CORS)
        .layer(CorsLayer::permissive()) 
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::info!("[server] started on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}