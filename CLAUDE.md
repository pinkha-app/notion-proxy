# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A small Rust HTTP service that acts as a backend-for-frontend between the **pinkha** iOS app and **Notion's OAuth API**. It exists for two reasons:

1. The Notion `client_secret` must not ship in the iOS binary, so the token exchange happens here.
2. Notion requires HTTPS redirect URIs, so this service receives the OAuth redirect and bounces the browser back to the `pinkha://` custom scheme.

Companion repo `../pinkha` (iOS app) signs requests to this proxy; the two repos work as one system.

## Commands

```bash
cargo run                    # local dev server on $PORT (default 3000)
cargo test                   # full test suite (unit + integration in tests/)
cargo test <name>            # single test by name substring
cargo test --test e2e        # only the e2e integration file
cargo fmt --all -- --check   # format check (CI + pre-commit gate)
cargo clippy --all-targets -- -D warnings   # lint gate
cargo llvm-cov --all-targets # local coverage; CI fails under 90% lines (main.rs excluded)
cargo audit                  # CVE scan (run in CI on every PR)
```

Pre-commit hook lives in `.githooks/pre-commit` and runs fmt + clippy + test. Enable per clone with `git config core.hooksPath .githooks`.

## Architecture

Hexagonal layout. Each layer owns one concern; the dependency arrow points inward (`interface` → `application` → `domain`; `infrastructure` implements `domain` ports).

- **`domain/`** — pure logic, no I/O. `signature.rs` is the HMAC-SHA256 verification (timestamp + nonce + body; ±300s clock window — see `TIMESTAMP_WINDOW_SECS`). `ports.rs` defines the `NotionGateway` and `Clock` traits.
- **`application/exchange_token.rs`** — the one use case. Verifies signature → parses body → calls `NotionGateway`. All branches return typed `ExchangeTokenError` variants; do not leak raw upstream errors here.
- **`infrastructure/`** — concrete adapters: `NotionHttpGateway` (reqwest call to `https://api.notion.com/v1/oauth/token`), `SystemClock`, `Config::from_env`.
- **`interface/`** — axum router, handlers, error mapping, CORS, state. Handlers translate HTTP ↔ use case input/output and nothing else.

### Request signing protocol

Every `POST /oauth/token` carries three headers:

- `X-Pinkha-Timestamp` — unix seconds
- `X-Pinkha-Nonce` — random per-request
- `X-Pinkha-Signature` — hex(HMAC_SHA256(secret, `"{ts}\n{nonce}\n{body}"`))

The same scheme is implemented in the iOS app (`NotionOAuth2.proxyHmacSecret`). Secret comes from `PROXY_HMAC_SECRET` and must match both sides exactly. Window is ±300s; nonce isn't currently replay-cached server-side (the short window is the replay defense).

### Endpoints

- `POST /oauth/token` — signed, returns Notion's token response as JSON.
- `GET /oauth/callback` — unsigned browser redirect. Forwards `code`/`state`/`error` to `pinkha://oauth/notion`. Notion's `code` is single-use and short-lived, which is why this endpoint is unauthenticated.
- `GET /health` — liveness.

Global middleware (order matters in `routes.rs`): CORS → Sentry hub → Sentry HTTP layer (continues distributed trace from iOS) → `tower_governor` rate limit. The governor uses `SmartIpKeyExtractor` because on AWS Lambda Function URLs there's no peer socket; the default `PeerIpKeyExtractor` would 500 every request.

### Runtime split (Lambda vs local)

`main.rs` checks `AWS_LAMBDA_FUNCTION_NAME`: if present, the axum service is handed to `lambda_http::run`; otherwise it runs on a TCP listener. The same binary works both ways. `Cargo.toml` release profile is tuned for Lambda cold-start (strip + fat LTO + `panic = "abort"` + 1 codegen unit).

`reqwest` and `sentry` are configured with `rustls` (no native-tls / OpenSSL) so the Linux ARM64 cross-compile from macOS works.

## Required env vars

`NOTION_CLIENT_ID`, `NOTION_CLIENT_SECRET`, `PROXY_HMAC_SECRET` are required (panic on startup if missing). `NOTION_BASE_URL`, `ALLOWED_ORIGINS`, `SENTRY_DSN`, `PORT` are optional with defaults. `NOTION_BASE_URL` is what e2e tests override to point at wiremock. See `.env.example`.

## Branch workflow

Three-branch promotion chain enforced by `.github/workflows/branch-policy.yml`:

```
dev → staging → master
```

PRs to `staging` must come from `dev`; PRs to `master` must come from `staging`. CI (`ci.yml`) runs tests + cargo-audit + llvm-cov on every push/PR to `dev` or `master`.

## Tests

- Unit tests live next to the code they test (`#[cfg(test)] mod tests`). Most use case branches and signature edge cases are covered there.
- `tests/e2e.rs` — full chain through the real `NotionHttpGateway` against a `wiremock` mock of `api.notion.com`.
- `tests/http.rs` — handler-level HTTP tests.
- `infrastructure::config` tests mutate `env::*` and are gated with `#[serial]` (via `serial_test`) so they don't race.
