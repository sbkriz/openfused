use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};
use std::path::PathBuf;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

use crate::store::{ContextStore, FileEntry};

pub async fn serve(store_path: PathBuf, bind: &str, port: u16) {
    let store = Arc::new(ContextStore::new(store_path));

    let app = Router::new()
        .route("/", get(root))
        .route("/ls", get(list_root))
        .route("/ls/{*path}", get(list_dir))
        .route("/read/{*path}", get(read_file))
        .route("/config", get(get_config))
        .layer(CorsLayer::permissive())
        .with_state(store);

    let addr = format!("{}:{}", bind, port);
    tracing::info!("OpenFuse daemon listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn root() -> &'static str {
    "openfused v0.2.0 — context mesh daemon"
}

async fn get_config(State(store): State<Arc<ContextStore>>) -> Result<Json<serde_json::Value>, StatusCode> {
    let config = store.config().await.ok_or(StatusCode::NOT_FOUND)?;
    // Only expose public info — not private keys or trusted keys
    Ok(Json(serde_json::json!({
        "id": config.id,
        "name": config.name,
        "publicKey": config.public_key,
    })))
}

async fn list_root(State(store): State<Arc<ContextStore>>) -> Json<Vec<FileEntry>> {
    Json(store.list_root().await)
}

async fn list_dir(
    State(store): State<Arc<ContextStore>>,
    Path(path): Path<String>,
) -> Result<Json<Vec<FileEntry>>, StatusCode> {
    // Only allow listing safe directories
    if !["shared", "knowledge"].contains(&path.as_str()) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(Json(store.list_dir(&path).await))
}

async fn read_file(
    State(store): State<Arc<ContextStore>>,
    Path(path): Path<String>,
) -> Result<Vec<u8>, StatusCode> {
    store.read_file(&path).await.ok_or(StatusCode::NOT_FOUND)
}
