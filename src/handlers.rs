use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Json, Redirect, Response},
};
use base64::{engine::general_purpose, Engine};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::sync::Arc;

use crate::captcha::{CaptchaResponse, CaptchaState, generate_captcha_image};
use crate::db::{
    AppState, authorize, generate_unique_code, add_link_to_session, fetch_links_by_ids,
    cleanup_session_if_empty, delete_links_by_codes, update_links_by_edits, is_phishing_domain,
};
use crate::{
    authorize_session, calculate_captcha_rounds, check_and_rotate_session,
    check_captcha_rate_limit, check_rate_limit, check_session_rate_limit, clearance_create_cookie,
    clearance_visit_cookie, csrf_cookie, generate_csrf_token, get_captcha_failures, get_client_ip,
    get_cookie, get_session, session_cookie, timestamp, validate_custom_code, validate_link_ids,
    validate_url, verify_csrf_token, CaptchaVerificationResult, SessionData, CODE_LENGTH,
    MAX_CUSTOM_CODE_LENGTH, verify_captcha_solution, LinkPreview,
};
use crate::{BulkEditItem, Link};

pub const MAX_REQUESTS_PER_MINUTE: u32 = 30;
pub const MAX_PREVIEW_PER_MINUTE: u32 = 20;
pub const MAX_SHORTEN_RANDOM_PER_MINUTE: u32 = 5;
pub const MAX_SHORTEN_CUSTOM_PER_MINUTE: u32 = 3;
pub const MAX_CAPTCHA_ROUNDS: u8 = 5;
pub const MAX_BULK_OPERATIONS: usize = 100;

#[derive(Deserialize)]
pub struct ShortenRequest {
    pub url: String,
    pub encrypted: Option<bool>,
    pub custom_code: Option<String>,
    pub signature: Option<String>,
    pub captcha_token: Option<String>,
    pub captcha_answers: Option<Vec<u8>>,
    pub csrf_token: Option<String>,
    pub require_captcha: Option<bool>,
    pub show_page: Option<bool>,
}

#[derive(Deserialize)]
pub struct BulkDeleteRequest {
    pub codes: Vec<String>,
    pub csrf_token: String,
}

#[derive(Deserialize)]
pub struct BulkEditRequest {
    pub edits: Vec<BulkEditItem>,
    pub csrf_token: String,
}

#[derive(Deserialize)]
pub struct CaptchaVerifyRequest {
    pub captcha_token: String,
    pub captcha_answers: Vec<u8>,
}

pub fn json_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        format!(r#"{{"error":"{}"}}"#, message),
    )
        .into_response()
}

pub fn json_response<T: Serialize>(data: &T) -> Response {
    Json(data).into_response()
}

pub fn validate_content_type(headers: &HeaderMap) -> Result<(), Box<Response>> {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(';').next())
        .filter(|s| s.trim() == "application/json")
        .map(|_| ())
        .ok_or_else(|| Box::new(json_error(StatusCode::BAD_REQUEST, "Invalid Content-Type")))
}

pub fn build_response_with_session(
    status: StatusCode,
    content_type: &str,
    body: String,
    state: &AppState,
    session: &SessionData,
    clearance_token: Option<String>,
) -> Response {
    let new_csrf = generate_csrf_token(&state.captcha, session);
    let mut response = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::SET_COOKIE, session_cookie(&state.captcha, session))
        .header(header::SET_COOKIE, csrf_cookie(&new_csrf));

    if let Some(token) = clearance_token {
        response = response.header(header::SET_COOKIE, clearance_create_cookie(&token));
    }

    response.body(body.into()).unwrap()
}

pub fn generate_captcha_challenge(state: &AppState, rounds: u8, request_hash: &str) -> Response {
    let (token, challenge) = state.captcha.create_challenge(rounds, request_hash);
    let image = generate_captcha_image(&state.captcha, &challenge);
    json_response(&CaptchaResponse {
        token,
        image: general_purpose::STANDARD.encode(&image),
        rounds: challenge.rounds,
    })
}

pub async fn verify_captcha_token(
    state: &AppState,
    token: &str,
    answers: &[u8],
    request_hash: &str,
    ip: &str,
    base_rounds: u8,
) -> Result<(), Response> {
    use verify_captcha_solution;

    match verify_captcha_solution(state, token, answers, request_hash, ip, base_rounds).await {
        CaptchaVerificationResult::Success => Ok(()),
        CaptchaVerificationResult::Failed { rounds } => {
            Err(generate_captcha_challenge(state, rounds, request_hash))
        }
        CaptchaVerificationResult::InvalidRequest => {
            Err(json_error(StatusCode::BAD_REQUEST, "Invalid request"))
        }
    }
}

pub fn build_html_response(
    html: String,
    session_cookie_val: String,
    csrf_cookie_val: String,
) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::SET_COOKIE, session_cookie_val)
        .header(header::SET_COOKIE, csrf_cookie_val)
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::X_FRAME_OPTIONS, "DENY")
        .header("X-XSS-Protection", "1; mode=block")
        .header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; \
         style-src 'self' 'unsafe-inline'; img-src 'self' data:; \
         form-action 'self'; frame-ancestors 'none'; base-uri 'self'",
        )
        .header("Referrer-Policy", "strict-origin-when-cross-origin")
        .header(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=()",
        )
        .header("Cross-Origin-Opener-Policy", "same-origin")
        .header("Cross-Origin-Resource-Policy", "same-origin")
        .header(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )
        .body(html.into())
        .unwrap()
}

pub async fn serve_index(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    serve_index_with_data(State(state), headers, None).await
}

async fn serve_index_with_data(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    initial_data: Option<Response>,
) -> Response {
    let html = tokio::fs::read_to_string("build/index.html")
        .await
        .unwrap_or_default();
    let session = check_and_rotate_session(&state, get_session(&state.captcha, &headers)).await;
    let csrf_token = generate_csrf_token(&state.captcha, &session);

    let html_with_data = if let Some(data_response) = initial_data {
        let body_bytes = axum::body::to_bytes(data_response.into_body(), usize::MAX)
            .await
            .unwrap_or_default();
        let data_json = String::from_utf8_lossy(&body_bytes);
        let script_tag = format!(
            r#"<script type="application/json" id="initial-data">{}</script>"#,
            data_json
        );

        if let Some(pos) = html.find("<script") {
            format!("{}{}{}", &html[..pos], script_tag, &html[pos..])
        } else {
            html.replace("</body>", &format!("{}</body>", script_tag))
        }
    } else {
        html
    };

    build_html_response(
        html_with_data,
        session_cookie(&state.captcha, &session),
        csrf_cookie(&csrf_token),
    )
}

pub async fn serve_privacy() -> Response {
    let html = tokio::fs::read_to_string("build/privacy.html")
        .await
        .unwrap_or_else(|_| String::from("404 Not Found"));

    build_html_response(html, String::new(), String::new())
}

pub async fn serve_terms() -> Response {
    let html = tokio::fs::read_to_string("build/terms.html")
        .await
        .unwrap_or_else(|_| String::from("404 Not Found"));

    build_html_response(html, String::new(), String::new())
}

pub async fn serve_404() -> Response {
    let html = tokio::fs::read_to_string("build/404.html")
        .await
        .unwrap_or_else(|_| String::from("404 Not Found"));

    let mut response = build_html_response(html, String::new(), String::new());
    *response.status_mut() = StatusCode::NOT_FOUND;
    response
}

pub async fn shorten(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ShortenRequest>,
) -> Result<Response, Response> {
    validate_content_type(&headers).map_err(|e| *e)?;

    let ip = get_client_ip(&headers)
        .ok_or_else(|| json_error(StatusCode::BAD_REQUEST, "Invalid request"))?;

    let rate_limit = if req.custom_code.is_some() {
        MAX_SHORTEN_CUSTOM_PER_MINUTE
    } else {
        MAX_SHORTEN_RANDOM_PER_MINUTE
    };

    check_rate_limit(&state, &ip, rate_limit)
        .await
        .map_err(|_| json_error(StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded"))?;

    let session = get_session(&state.captcha, &headers);

    check_session_rate_limit(&state, &session)
        .await
        .map_err(|_| json_error(StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded"))?;

    if !verify_csrf_token(
        &state.captcha,
        req.csrf_token.as_deref().unwrap_or(""),
        &session,
    ) {
        return Err(json_error(StatusCode::FORBIDDEN, "Invalid CSRF token"));
    }

    let encrypted = req.encrypted.unwrap_or(false);

    if !encrypted && !validate_url(&req.url, &headers) {
        return Err(json_error(StatusCode::BAD_REQUEST, "Invalid request"));
    }

    if !encrypted && is_phishing_domain(&state.phishing_filter, &req.url).await {
        return Err(json_error(StatusCode::BAD_REQUEST, "Invalid request"));
    }

    if encrypted && (req.url.is_empty() || req.url.len() > 4096) {
        return Err(json_error(StatusCode::BAD_REQUEST, "Invalid request"));
    }

    let has_clearance = get_cookie(&headers, "ripplit_clearance_create")
        .map(|t| state.captcha.verify_clearance(&t, &ip, "create"))
        .unwrap_or(false);

    let has_custom = req.custom_code.is_some();
    let failures = get_captcha_failures(&state, &ip).await;
    let rounds = calculate_captcha_rounds(has_clearance, has_custom, failures);

    if rounds > 0 {
        check_captcha_rate_limit(&state, &ip)
            .await
            .map_err(|_| json_error(StatusCode::TOO_MANY_REQUESTS, "Too many captcha requests"))?;

        let request_hash =
            CaptchaState::hash_request(&req.url, encrypted, &req.custom_code, &req.signature);

        if let (Some(token), Some(answers)) = (&req.captcha_token, &req.captcha_answers) {
            let base_rounds = match (has_clearance, has_custom) {
                (false, false) => 2,
                (true, true) => 1,
                (false, true) => 3,
                (true, false) => 0,
            };
            verify_captcha_token(&state, token, answers, &request_hash, &ip, base_rounds).await?;
        } else {
            return Ok(generate_captcha_challenge(&state, rounds, &request_hash));
        }
    }

    if authorize(&state.pool, &session.nonce)
        .await
        .is_err()
    {
        sqlx::query("INSERT INTO sessions (session_id, link_ids, last_rotated) VALUES ($1, '', $2)")
            .bind(&session.nonce)
            .bind(session.last_rotated as i64)
            .execute(&state.pool)
            .await
            .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;
    }

    let code = match req.custom_code {
        Some(c) if validate_custom_code(&c) => c,
        Some(_) => return Err(json_error(StatusCode::BAD_REQUEST, "Invalid request")),
        None => generate_unique_code(&state.pool, CODE_LENGTH)
            .await
            .map_err(|_| {
                json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate code")
            })?,
    };

    let result = sqlx::query(
        "INSERT INTO links (code, original_url, encrypted, created_at, signature, \
         require_captcha, show_page) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
    )
    .bind(&code)
    .bind(&req.url)
    .bind(encrypted)
    .bind(timestamp() as i64)
    .bind(&req.signature)
    .bind(req.require_captcha.unwrap_or(false))
    .bind(req.show_page.unwrap_or(false) || encrypted)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| {
        if e.to_string().contains("duplicate key") {
            json_error(StatusCode::CONFLICT, "Code already exists")
        } else {
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error")
        }
    })?;

    let link_id: i64 = result.get(0);

    add_link_to_session(&state.pool, &session.nonce, link_id)
        .await
        .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;

    let session = check_and_rotate_session(&state, session).await;
    let clearance_token = if !has_clearance {
        Some(state.captcha.generate_clearance(&ip, "create"))
    } else {
        None
    };

    Ok(build_response_with_session(
        StatusCode::OK,
        "text/plain",
        code,
        &state,
        &session,
        clearance_token,
    ))
}

pub async fn redirect(
    State(state): State<Arc<AppState>>,
    Path(code): Path<String>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    if code.len() > MAX_CUSTOM_CODE_LENGTH + 1 || code.ends_with('+') {
        return Ok(serve_index(State(state.clone()), headers).await);
    }

    let actual_code = code.trim_end_matches('+');

    let link = sqlx::query_as::<_, Link>(
        "SELECT id, code, original_url, encrypted, created_at, clicks, \
         signature, require_captcha, show_page FROM links WHERE code = $1",
    )
    .bind(actual_code)
    .fetch_one(&state.pool)
    .await
    .map_err(|_| StatusCode::NOT_FOUND)?;

    if link.require_captcha {
        let ip = get_client_ip(&headers).ok_or(StatusCode::BAD_REQUEST)?;
        let has_clearance = get_cookie(&headers, "ripplit_clearance_visit")
            .map(|t| state.captcha.verify_clearance(&t, &ip, "visit"))
            .unwrap_or(false);

        if !has_clearance {
            let failures = get_captcha_failures(&state, &ip).await;
            let rounds = calculate_captcha_rounds(true, true, failures);
            let request_hash = CaptchaState::hash_request(&code, false, &None, &None);
            let initial_data = generate_captcha_challenge(&state, rounds, &request_hash);
            return Ok(serve_index_with_data(State(state), headers, Some(initial_data)).await);
        }
    }

    let _ = sqlx::query(
        "UPDATE links SET clicks = CASE WHEN clicks < $1 THEN clicks + 1 \
         ELSE clicks END WHERE code = $2",
    )
    .bind(i64::MAX - 1)
    .bind(actual_code)
    .execute(&state.pool)
    .await;

    if link.encrypted || link.show_page {
        let preview = LinkPreview {
            code: link.code.clone(),
            original_url: link.original_url.clone(),
            encrypted: link.encrypted,
            created_at: link.created_at,
            clicks: link.clicks,
            signature: link.signature.clone(),
        };
        let initial_data = json_response(&preview);
        return Ok(serve_index_with_data(State(state), headers, Some(initial_data)).await);
    }

    if validate_url(&link.original_url, &headers) {
        Ok(Redirect::to(&link.original_url).into_response())
    } else {
        let preview = LinkPreview {
            code: link.code.clone(),
            original_url: link.original_url.clone(),
            encrypted: link.encrypted,
            created_at: link.created_at,
            clicks: link.clicks,
            signature: link.signature.clone(),
        };
        let initial_data = json_response(&preview);
        Ok(serve_index_with_data(State(state), headers, Some(initial_data)).await)
    }
}

pub async fn list_links(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let ip = get_client_ip(&headers).ok_or(StatusCode::BAD_REQUEST)?;
    check_rate_limit(&state, &ip, MAX_REQUESTS_PER_MINUTE).await?;

    let session = get_session(&state.captcha, &headers);
    let link_ids = authorize(&state.pool, &session.nonce)
        .await
        .unwrap_or_default();
    let links = fetch_links_by_ids(&state.pool, &link_ids)
        .await
        .unwrap_or_default();

    let session = check_and_rotate_session(&state, session).await;
    let new_csrf = generate_csrf_token(&state.captcha, &session);

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::SET_COOKIE, session_cookie(&state.captcha, &session))
        .header(header::SET_COOKIE, csrf_cookie(&new_csrf))
        .body(serde_json::to_string(&links).unwrap().into())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

pub async fn delete_link(
    State(state): State<Arc<AppState>>,
    Path(code): Path<String>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let ip = get_client_ip(&headers).ok_or(StatusCode::BAD_REQUEST)?;
    check_rate_limit(&state, &ip, MAX_REQUESTS_PER_MINUTE).await?;

    let session = get_session(&state.captcha, &headers);
    let csrf_token = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !verify_csrf_token(&state.captcha, csrf_token, &session) {
        return Ok(json_response(&serde_json::json!({
            "success": false, "error": "Invalid CSRF token"
        })));
    }

    let link_ids = authorize(&state.pool, &session.nonce)
        .await
        .unwrap_or_default();
    if !validate_link_ids(&link_ids) {
        return Ok(json_response(&serde_json::json!({"success": false})));
    }

    let mut query_builder = sqlx::QueryBuilder::new("DELETE FROM links WHERE code = ");
    query_builder.push_bind(&code);
    query_builder.push(" AND id IN (");
    let mut separated = query_builder.separated(", ");
    for id in &link_ids {
        separated.push_bind(id);
    }
    separated.push_unseparated(")");

    let deleted = query_builder
        .build()
        .execute(&state.pool)
        .await
        .map(|r| r.rows_affected())
        .unwrap_or(0);

    if deleted > 0 {
        let _ = cleanup_session_if_empty(&state.pool, &session.nonce).await;
    }

    let session = check_and_rotate_session(&state, session).await;
    Ok(build_response_with_session(
        StatusCode::OK,
        "application/json",
        serde_json::to_string(&serde_json::json!({"success": deleted > 0})).unwrap(),
        &state,
        &session,
        None,
    ))
}

pub async fn update_link(
    State(state): State<Arc<AppState>>,
    Path(code): Path<String>,
    headers: HeaderMap,
    Json(req): Json<ShortenRequest>,
) -> Result<Response, Response> {
    validate_content_type(&headers).map_err(|e| *e)?;

    let ip = get_client_ip(&headers)
        .ok_or_else(|| json_error(StatusCode::BAD_REQUEST, "Invalid request"))?;

    check_rate_limit(&state, &ip, MAX_REQUESTS_PER_MINUTE)
        .await
        .map_err(|_| json_error(StatusCode::TOO_MANY_REQUESTS, "Rate limit"))?;

    let session = get_session(&state.captcha, &headers);

    if !verify_csrf_token(
        &state.captcha,
        req.csrf_token.as_deref().unwrap_or(""),
        &session,
    ) {
        return Err(json_error(StatusCode::FORBIDDEN, "Invalid CSRF token"));
    }

    let encrypted = req.encrypted.unwrap_or(false);

    if !encrypted && !validate_url(&req.url, &headers) {
        return Err(json_error(StatusCode::BAD_REQUEST, "Invalid URL"));
    }

    if !encrypted && is_phishing_domain(&state.phishing_filter, &req.url).await {
        return Err(json_error(StatusCode::BAD_REQUEST, "Invalid URL"));
    }

    let link_ids = authorize_session(&state.pool, &session.nonce)
        .await
        .map_err(|_| json_error(StatusCode::UNAUTHORIZED, "Unauthorized"))?;
    if !validate_link_ids(&link_ids) {
        return Err(json_error(StatusCode::BAD_REQUEST, "Invalid session"));
    }

    let mut query_builder = sqlx::QueryBuilder::new("UPDATE links SET original_url = ");
    query_builder.push_bind(&req.url);
    query_builder.push(", signature = ");
    query_builder.push_bind(&req.signature);
    query_builder.push(" WHERE code = ");
    query_builder.push_bind(&code);
    query_builder.push(" AND id IN (");
    let mut separated = query_builder.separated(", ");
    for id in &link_ids {
        separated.push_bind(id);
    }
    separated.push_unseparated(")");

    let updated = query_builder
        .build()
        .execute(&state.pool)
        .await
        .map(|r| r.rows_affected())
        .unwrap_or(0);

    let session = check_and_rotate_session(&state, session).await;
    Ok(build_response_with_session(
        StatusCode::OK,
        "application/json",
        serde_json::to_string(&serde_json::json!({"success": updated > 0})).unwrap(),
        &state,
        &session,
        None,
    ))
}

pub async fn get_link_preview(
    State(state): State<Arc<AppState>>,
    Path(code): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let ip = get_client_ip(&headers)
        .ok_or_else(|| json_error(StatusCode::BAD_REQUEST, "Invalid request"))?;

    check_rate_limit(&state, &ip, MAX_PREVIEW_PER_MINUTE)
        .await
        .map_err(|_| json_error(StatusCode::TOO_MANY_REQUESTS, "Rate limit"))?;

    let is_preview = headers
        .get("x-preview")
        .and_then(|v| v.to_str().ok())
        .map(|s| s == "1")
        .unwrap_or(false);

    let _ = sqlx::query(
        "UPDATE links SET clicks = CASE WHEN clicks < $1 THEN clicks + 1 \
         ELSE clicks END WHERE code = $2",
    )
    .bind(i64::MAX - 1)
    .bind(&code)
    .execute(&state.pool)
    .await;

    let link = sqlx::query_as::<_, Link>(
        "SELECT id, code, original_url, encrypted, created_at, clicks, \
         signature, require_captcha, show_page FROM links WHERE code = $1",
    )
    .bind(&code)
    .fetch_one(&state.pool)
    .await
    .map_err(|_| json_error(StatusCode::NOT_FOUND, "Link not found"))?;

    if link.require_captcha {
        let is_owner = if is_preview {
            let session = get_session(&state.captcha, &headers);
            authorize(&state.pool, &session.nonce)
                .await
                .ok()
                .map(|link_ids| link_ids.contains(&link.id))
                .unwrap_or(false)
        } else {
            false
        };

        if !is_owner {
            let has_clearance = get_cookie(&headers, "ripplit_clearance_visit")
                .map(|t| state.captcha.verify_clearance(&t, &ip, "visit"))
                .unwrap_or(false);

            if !has_clearance {
                check_captcha_rate_limit(&state, &ip).await.map_err(|_| {
                    json_error(StatusCode::TOO_MANY_REQUESTS, "Too many captcha requests")
                })?;

                let failures = get_captcha_failures(&state, &ip).await;
                let rounds = calculate_captcha_rounds(false, false, failures);
                let request_hash = CaptchaState::hash_request(&code, false, &None, &None);
                return Ok(generate_captcha_challenge(&state, rounds, &request_hash));
            }
        }
    }

    Ok(json_response(&LinkPreview {
        code: link.code,
        original_url: link.original_url,
        encrypted: link.encrypted,
        created_at: link.created_at,
        clicks: link.clicks,
        signature: link.signature,
    }))
}

pub async fn bulk_delete_links(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<BulkDeleteRequest>,
) -> Result<Response, Response> {
    validate_content_type(&headers).map_err(|e| *e)?;

    let ip = get_client_ip(&headers)
        .ok_or_else(|| json_error(StatusCode::BAD_REQUEST, "Invalid request"))?;

    check_rate_limit(&state, &ip, MAX_REQUESTS_PER_MINUTE)
        .await
        .map_err(|_| json_error(StatusCode::TOO_MANY_REQUESTS, "Rate limit"))?;

    if req.codes.is_empty() {
        return Err(json_error(StatusCode::BAD_REQUEST, "No codes provided"));
    }

    if req.codes.len() > MAX_BULK_OPERATIONS {
        return Err(json_error(StatusCode::BAD_REQUEST, "Too many codes"));
    }

    let session = get_session(&state.captcha, &headers);

    if !verify_csrf_token(&state.captcha, &req.csrf_token, &session) {
        return Err(json_error(StatusCode::FORBIDDEN, "Invalid CSRF token"));
    }

    let link_ids = authorize_session(&state.pool, &session.nonce)
        .await
        .map_err(|_| json_error(StatusCode::UNAUTHORIZED, "Unauthorized"))?;

    let total = delete_links_by_codes(&state.pool, &req.codes, &link_ids)
        .await
        .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;

    if total > 0 {
        let _ = cleanup_session_if_empty(&state.pool, &session.nonce).await;
    }

    let session = check_and_rotate_session(&state, session).await;
    Ok(build_response_with_session(
        StatusCode::OK,
        "application/json",
        serde_json::to_string(&serde_json::json!({"success": true, "deleted": total})).unwrap(),
        &state,
        &session,
        None,
    ))
}

pub async fn bulk_edit_links(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<BulkEditRequest>,
) -> Result<Response, Response> {
    validate_content_type(&headers).map_err(|e| *e)?;

    let ip = get_client_ip(&headers)
        .ok_or_else(|| json_error(StatusCode::BAD_REQUEST, "Invalid request"))?;

    check_rate_limit(&state, &ip, MAX_REQUESTS_PER_MINUTE)
        .await
        .map_err(|_| json_error(StatusCode::TOO_MANY_REQUESTS, "Rate limit"))?;

    if req.edits.is_empty() {
        return Err(json_error(StatusCode::BAD_REQUEST, "No edits provided"));
    }

    if req.edits.len() > MAX_BULK_OPERATIONS {
        return Err(json_error(StatusCode::BAD_REQUEST, "Too many edits"));
    }

    let session = get_session(&state.captcha, &headers);

    if !verify_csrf_token(&state.captcha, &req.csrf_token, &session) {
        return Err(json_error(StatusCode::FORBIDDEN, "Invalid CSRF token"));
    }

    for edit in &req.edits {
        if !edit.encrypted && !validate_url(&edit.url, &headers) {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                &format!("Invalid URL for code: {}", edit.code),
            ));
        }

        if !edit.encrypted && is_phishing_domain(&state.phishing_filter, &edit.url).await
        {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                &format!("Invalid URL for code: {}", edit.code),
            ));
        }
    }

    let link_ids = authorize_session(&state.pool, &session.nonce)
        .await
        .map_err(|_| json_error(StatusCode::UNAUTHORIZED, "Unauthorized"))?;

    let total = update_links_by_edits(&state.pool, &req.edits, &link_ids)
        .await
        .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;

    let session = check_and_rotate_session(&state, session).await;
    Ok(build_response_with_session(
        StatusCode::OK,
        "application/json",
        serde_json::to_string(&serde_json::json!({"success": true, "updated": total})).unwrap(),
        &state,
        &session,
        None,
    ))
}

pub async fn verify_link_captcha(
    State(state): State<Arc<AppState>>,
    Path(code): Path<String>,
    headers: HeaderMap,
    Json(req): Json<CaptchaVerifyRequest>,
) -> Result<Response, Response> {
    let ip = get_client_ip(&headers)
        .ok_or_else(|| json_error(StatusCode::BAD_REQUEST, "Invalid request"))?;

    check_rate_limit(&state, &ip, MAX_PREVIEW_PER_MINUTE)
        .await
        .map_err(|_| json_error(StatusCode::TOO_MANY_REQUESTS, "Rate limit"))?;

    let request_hash = CaptchaState::hash_request(&code, false, &None, &None);
    verify_captcha_token(
        &state,
        &req.captcha_token,
        &req.captcha_answers,
        &request_hash,
        &ip,
        2,
    )
    .await?;

    let clearance_token = state.captcha.generate_clearance(&ip, "visit");
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::SET_COOKIE, clearance_visit_cookie(&clearance_token))
        .body(r#"{"success":true}"#.into())
        .unwrap())
}
