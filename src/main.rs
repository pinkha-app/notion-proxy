use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tower_http::cors::{Any, CorsLayer};

// ── State ─────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    http: Client,
    notion_client_id: String,
    notion_client_secret: String,
}

// ── Request / Response types ──────────────────────────────────────────────────

#[derive(Deserialize)]
struct TokenRequest {
    code: String,
    redirect_uri: String,
}

#[derive(Serialize, Deserialize)]
struct NotionTokenResponse {
    access_token: String,
    token_type: String,
    bot_id: String,
    workspace_id: String,
    workspace_name: Option<String>,
    workspace_icon: Option<String>,
    owner: serde_json::Value,
    duplicated_template_id: Option<String>,
    request_id: Option<String>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

type AppError = (StatusCode, Json<ErrorResponse>);

fn err(status: StatusCode, msg: impl Into<String>) -> AppError {
    (status, Json(ErrorResponse { error: msg.into() }))
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn exchange_token(
    State(state): State<Arc<AppState>>,
    Json(body): Json<TokenRequest>,
) -> Result<Json<NotionTokenResponse>, AppError> {
    if body.code.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "code is required"));
    }

    let response = state
        .http
        .post("https://api.notion.com/v1/oauth/token")
        .basic_auth(&state.notion_client_id, Some(&state.notion_client_secret))
        .header("Notion-Version", "2022-06-28")
        .json(&serde_json::json!({
            "grant_type": "authorization_code",
            "code": body.code,
            "redirect_uri": body.redirect_uri,
        }))
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Notion token exchange network error: {e}");
            err(StatusCode::BAD_GATEWAY, "upstream unreachable")
        })?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        tracing::error!("Notion returned {status}: {text}");
        return Err(err(StatusCode::BAD_GATEWAY, text));
    }

    let token = response.json::<NotionTokenResponse>().await.map_err(|e| {
        tracing::error!("Failed to parse Notion response: {e}");
        err(StatusCode::INTERNAL_SERVER_ERROR, "parse error")
    })?;

    tracing::info!(workspace_id = %token.workspace_id, "token exchanged successfully");
    Ok(Json(token))
}

async fn health() -> &'static str {
    "ok"
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    // Load .env in local dev (no-op in prod where Railway injects env vars).
    dotenvy::dotenv().ok();

    let dsn = std::env::var("SENTRY_DSN").unwrap_or_default();
    let guard = sentry::init((
        dsn,
        sentry::ClientOptions {
            release: sentry::release_name!(),
            traces_sample_rate: 0.1,
            ..Default::default()
        },
    ));
    Box::leak(Box::new(guard));

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "notion_proxy=info".into()),
        )
        .init();

    let state = Arc::new(AppState {
        http: Client::new(),
        notion_client_id: std::env::var("NOTION_CLIENT_ID")
            .expect("NOTION_CLIENT_ID is required"),
        notion_client_secret: std::env::var("NOTION_CLIENT_SECRET")
            .expect("NOTION_CLIENT_SECRET is required"),
    });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/oauth/token", post(exchange_token))
        .route("/health", get(health))
        .layer(sentry_tower::SentryLayer::new_from_top())
        .layer(cors)
        .with_state(state);

    // Railway injects PORT automatically; fallback to 3000 for local dev.
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".into());
    let addr: SocketAddr = format!("0.0.0.0:{port}").parse().unwrap();
    tracing::info!("listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
