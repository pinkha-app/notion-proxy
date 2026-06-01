use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Json, Redirect},
    routing::{get, post},
    Router,
};
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use tower_http::cors::{AllowOrigin, CorsLayer};

type HmacSha256 = Hmac<Sha256>;

const TIMESTAMP_WINDOW_SECS: i64 = 300;

// ── State ─────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    http: Client,
    notion_client_id: String,
    notion_client_secret: String,
    hmac_secret: Vec<u8>,
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

// ── HMAC verification ─────────────────────────────────────────────────────────

fn verify_signature(state: &AppState, headers: &HeaderMap, body: &[u8]) -> Result<(), AppError> {
    let ts = headers
        .get("x-pinkha-timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "missing X-Pinkha-Timestamp"))?;
    let nonce = headers
        .get("x-pinkha-nonce")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "missing X-Pinkha-Nonce"))?;
    let sig = headers
        .get("x-pinkha-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "missing X-Pinkha-Signature"))?;

    let ts_int: i64 = ts
        .parse()
        .map_err(|_| err(StatusCode::UNAUTHORIZED, "invalid timestamp"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if (now - ts_int).abs() > TIMESTAMP_WINDOW_SECS {
        return Err(err(StatusCode::UNAUTHORIZED, "timestamp out of window"));
    }

    let sig_bytes =
        hex::decode(sig).map_err(|_| err(StatusCode::UNAUTHORIZED, "invalid signature encoding"))?;

    let mut mac =
        HmacSha256::new_from_slice(&state.hmac_secret).expect("HMAC accepts any key length");
    mac.update(ts.as_bytes());
    mac.update(b"\n");
    mac.update(nonce.as_bytes());
    mac.update(b"\n");
    mac.update(body);

    mac.verify_slice(&sig_bytes)
        .map_err(|_| err(StatusCode::UNAUTHORIZED, "invalid signature"))
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn exchange_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<NotionTokenResponse>, AppError> {
    verify_signature(&state, &headers, &body)?;

    let req: TokenRequest = serde_json::from_slice(&body)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "invalid JSON body"))?;

    if req.code.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "code is required"));
    }

    let response = state
        .http
        .post("https://api.notion.com/v1/oauth/token")
        .basic_auth(&state.notion_client_id, Some(&state.notion_client_secret))
        .header("Notion-Version", "2022-06-28")
        .json(&serde_json::json!({
            "grant_type": "authorization_code",
            "code": req.code,
            "redirect_uri": req.redirect_uri,
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

// ── OAuth callback bridge ─────────────────────────────────────────────────────
//
// Notion requires HTTPS redirect URIs since 2024, so the iOS app's custom
// `pinkha://` scheme can no longer be registered directly with Notion.
// Instead, this HTTPS endpoint is what Notion redirects to after the user
// consents, and we immediately bounce the browser to `pinkha://oauth/notion`
// with the same query string. iOS's `ASWebAuthenticationSession` is watching
// for that scheme and snaps back into the app.
//
// No HMAC: this is a browser-initiated GET, not a signed app request. The
// `code` carried by Notion is single-use and short-lived, so there's nothing
// for an attacker to replay.

#[derive(Deserialize)]
struct OAuthCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

async fn oauth_callback(Query(q): Query<OAuthCallbackQuery>) -> impl IntoResponse {
    // Forward every relevant parameter to the iOS app. Notion may send
    // `error` instead of `code` if the user denied consent — let the app
    // handle that case.
    let mut target = String::from("pinkha://oauth/notion");
    let mut sep = '?';
    for (name, value) in [
        ("code", q.code.as_deref()),
        ("state", q.state.as_deref()),
        ("error", q.error.as_deref()),
    ] {
        if let Some(v) = value {
            // Minimal percent-encoding for query values — we only forward
            // tokens and short identifiers, never user-controlled HTML.
            let encoded = urlencoding::encode(v);
            target.push(sep);
            target.push_str(name);
            target.push('=');
            target.push_str(&encoded);
            sep = '&';
        }
    }
    Redirect::temporary(&target)
}

// ── CORS ──────────────────────────────────────────────────────────────────────

fn build_cors() -> CorsLayer {
    let raw = std::env::var("ALLOWED_ORIGINS").unwrap_or_default();
    let origins: Vec<HeaderValue> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| HeaderValue::from_str(s).ok())
        .collect();

    let layer = CorsLayer::new()
        .allow_methods([Method::POST, Method::GET, Method::OPTIONS])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderName::from_static("x-pinkha-timestamp"),
            axum::http::HeaderName::from_static("x-pinkha-nonce"),
            axum::http::HeaderName::from_static("x-pinkha-signature"),
        ]);

    if origins.is_empty() {
        // No browser origin allowed. The iOS app uses URLSession, which never
        // triggers CORS — so this is the safe default for a native-only client.
        layer
    } else {
        layer.allow_origin(AllowOrigin::list(origins))
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), lambda_http::Error> {
    let _ = dotenvy::dotenv();

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
        hmac_secret: std::env::var("PROXY_HMAC_SECRET")
            .expect("PROXY_HMAC_SECRET is required")
            .into_bytes(),
    });

    // Per-IP rate limit: 5 requests / minute, burst of 5.
    // NOTE: behind Railway's proxy the peer IP is the proxy; if we need true
    // client IPs, switch to a `SmartIpKeyExtractor` reading X-Forwarded-For.
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(12)
            .burst_size(5)
            .finish()
            .expect("valid governor config"),
    );

    // Sentry middleware ordering matters: `NewSentryLayer` must wrap every
    // request in its own hub *before* `SentryHttpLayer` reads the incoming
    // `sentry-trace` header to continue the distributed trace from the iOS
    // client. Without `with_transaction`, no transaction is created and the
    // trace ends at the proxy boundary.
    let app = Router::new()
        .route("/oauth/token", post(exchange_token))
        .route("/oauth/callback", get(oauth_callback))
        .route("/health", get(health))
        .layer(GovernorLayer::new(governor_conf))
        .layer(sentry_tower::SentryHttpLayer::new().enable_transaction())
        .layer(sentry_tower::NewSentryLayer::new_from_top())
        .layer(build_cors())
        .with_state(state);

    // Runtime split: AWS Lambda injects `AWS_LAMBDA_FUNCTION_NAME` into the
    // environment of every invocation. When present, hand the axum service to
    // `lambda_http::run`; otherwise fall back to the local TCP listener for
    // `cargo run` and integration tests.
    if std::env::var("AWS_LAMBDA_FUNCTION_NAME").is_ok() {
        tracing::info!("starting on Lambda runtime");
        lambda_http::run(app).await
    } else {
        let port = std::env::var("PORT").unwrap_or_else(|_| "3000".into());
        let addr = format!("0.0.0.0:{port}");
        tracing::info!("listening on {addr}");
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;
        Ok(())
    }
}
