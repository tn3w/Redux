mod captcha;
mod db;
mod handlers;
mod reports;

use axum::{
    http::{header, HeaderMap, StatusCode},
    routing::{delete, get, post},
    Router,
};
use base64::{engine::general_purpose, Engine};
use hmac::{Hmac, Mac};
use rand::{rng, RngExt};
use sha2::Sha256;
use std::{net::IpAddr, sync::Arc};
use subtle::ConstantTimeEq;
use redis::AsyncCommands;

use captcha::CaptchaState;
use db::{
    AppState, RATE_WINDOW, MAX_LINKS_PER_SESSION,
    init_db, init_phishing_filter, start_phishing_updater, migrate_session, authorize,
};
use handlers::{
    bulk_delete_links, bulk_edit_links, delete_link, get_link_preview, list_links, redirect,
    serve_404, serve_index, serve_privacy, serve_terms, shorten, update_link, verify_link_captcha,
};
use reports::{
    handle_review_action, serve_report, serve_report_with_token, submit_report,
    process_report_queue, REPORT_QUEUE_INTERVAL,
};

use serde::{Deserialize, Serialize};
use sqlx::PgPool;

type HmacSha256 = Hmac<Sha256>;

pub const MAX_URL_LENGTH: usize = 512;
pub const CODE_LENGTH: usize = 6;
pub const MAX_CUSTOM_CODE_LENGTH: usize = 24;
pub const SESSION_ROTATION_INTERVAL: u64 = 3600;

#[derive(sqlx::FromRow, Serialize)]
pub struct Link {
    pub id: i64,
    pub code: String,
    pub original_url: String,
    pub encrypted: bool,
    pub created_at: i64,
    pub clicks: i64,
    pub signature: Option<String>,
    pub require_captcha: bool,
    pub show_page: bool,
}

#[derive(Serialize)]
pub struct LinkPreview {
    pub code: String,
    pub original_url: String,
    pub encrypted: bool,
    pub created_at: i64,
    pub clicks: i64,
    pub signature: Option<String>,
}

#[derive(Deserialize)]
pub struct BulkEditItem {
    pub code: String,
    pub url: String,
    pub encrypted: bool,
    pub signature: Option<String>,
}

pub struct SessionData {
    pub nonce: String,
    pub created_at: u64,
    pub last_rotated: u64,
}

pub fn timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn random_string(length: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rng();
    (0..length)
        .map(|_| CHARS[rng.random_range(0..CHARS.len())] as char)
        .collect()
}

pub fn create_session_token(state: &CaptchaState, session: &SessionData) -> String {
    let payload = format!(
        "{}:{}:{}",
        session.nonce, session.created_at, session.last_rotated
    );
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&state.hmac_key).unwrap();
    mac.update(payload.as_bytes());
    let sig = general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{}.{}", payload, sig)
}

pub fn parse_session_token(state: &CaptchaState, token: &str) -> Option<SessionData> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 2 {
        return None;
    }

    let (payload, sig) = (parts[0], parts[1]);
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&state.hmac_key).unwrap();
    mac.update(payload.as_bytes());
    let expected = general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    let is_valid: bool = sig.as_bytes().ct_eq(expected.as_bytes()).into();

    if !is_valid {
        return None;
    }

    let payload_parts: Vec<&str> = payload.split(':').collect();
    if payload_parts.len() != 3 {
        return None;
    }

    let nonce = payload_parts[0].to_string();
    let created_at: u64 = payload_parts[1].parse().ok()?;
    let last_rotated: u64 = payload_parts[2].parse().ok()?;

    let nonce_len_bytes = (nonce.len() as u32).to_le_bytes();
    let expected_len_bytes = 32u32.to_le_bytes();
    let len_valid: bool = nonce_len_bytes.ct_eq(&expected_len_bytes).into();

    if !len_valid || !nonce.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }

    let now = timestamp();
    if now < created_at
        || now < last_rotated
        || last_rotated < created_at
        || now - created_at > 2592000
    {
        return None;
    }

    Some(SessionData {
        nonce,
        created_at,
        last_rotated,
    })
}

pub fn get_session(state: &CaptchaState, headers: &HeaderMap) -> SessionData {
    let now = timestamp();
    get_cookie(headers, "ripplit_session")
        .and_then(|t| parse_session_token(state, &t))
        .unwrap_or_else(|| SessionData {
            nonce: random_string(32),
            created_at: now,
            last_rotated: now,
        })
}

pub fn rotate_session(old: &SessionData) -> SessionData {
    SessionData {
        nonce: random_string(32),
        created_at: old.created_at,
        last_rotated: timestamp(),
    }
}

pub fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|cookie| {
            let mut parts = cookie.trim().splitn(2, '=');
            match (parts.next(), parts.next()) {
                (Some(key), Some(value)) if key == name => Some(value.to_string()),
                _ => None,
            }
        })
}

pub fn get_client_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .filter(|ip| validate_ip_format(ip))
        .map(|s| s.to_string())
}

fn validate_ip_format(ip: &str) -> bool {
    if let Ok(parsed) = ip.parse::<IpAddr>() {
        match parsed {
            IpAddr::V4(v4) => {
                !(v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_unspecified()
                    || v4.octets()[0] == 0
                    || (v4.octets()[0] == 169 && v4.octets()[1] == 254))
            }
            IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unspecified(),
        }
    } else {
        false
    }
}

pub async fn check_rate_limit(state: &AppState, ip: &str, limit: u32) -> Result<(), StatusCode> {
    let key = format!("rl:{}", ip);
    let mut conn = state.redis.clone();
    
    let count: u32 = conn.incr(&key, 1).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    if count == 1 {
        let _: () = conn.expire(&key, RATE_WINDOW as i64).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    
    if count > limit {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    
    Ok(())
}

pub async fn check_captcha_rate_limit(state: &AppState, ip: &str) -> Result<(), StatusCode> {
    let key = format!("crl:{}", ip);
    let mut conn = state.redis.clone();
    
    let count: u32 = conn.incr(&key, 1).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    if count == 1 {
        let _: () = conn.expire(&key, RATE_WINDOW as i64).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    
    if count > 5 {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    
    Ok(())
}

pub async fn get_captcha_failures(state: &AppState, ip: &str) -> u32 {
    let key = format!("cf:{}", ip);
    let mut conn = state.redis.clone();
    conn.get(&key).await.unwrap_or(0)
}

pub async fn record_captcha_failure(state: &AppState, ip: &str) {
    let key = format!("cf:{}", ip);
    let mut conn = state.redis.clone();
    let _: Result<u32, _> = conn.incr(&key, 1).await;
    let _: Result<(), _> = conn.expire(&key, 300).await;
}

pub async fn clear_captcha_failures(state: &AppState, ip: &str) {
    let key = format!("cf:{}", ip);
    let mut conn = state.redis.clone();
    let _: Result<(), _> = conn.del(&key).await;
}

pub async fn check_session_rate_limit(
    state: &AppState,
    session: &SessionData,
) -> Result<(), StatusCode> {
    let key = format!("srl:{}", session.created_at);
    let mut conn = state.redis.clone();
    
    let count: u32 = conn.incr(&key, 1).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    if count == 1 {
        let _: () = conn.expire(&key, RATE_WINDOW as i64).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    
    if count > 50 {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    
    Ok(())
}

pub fn session_cookie(state: &CaptchaState, session: &SessionData) -> String {
    format!(
        "ripplit_session={}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000",
        create_session_token(state, session)
    )
}

pub fn csrf_cookie(token: &str) -> String {
    format!(
        "ripplit_csrf={}; Path=/; Secure; SameSite=Strict; Max-Age=2592000",
        token
    )
}

pub fn clearance_create_cookie(token: &str) -> String {
    format!(
        "ripplit_clearance_create={}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600",
        token
    )
}

pub fn clearance_visit_cookie(token: &str) -> String {
    format!(
        "ripplit_clearance_visit={}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600",
        token
    )
}

pub fn generate_csrf_token(state: &CaptchaState, session: &SessionData) -> String {
    let payload = format!("{}:{}:{}", session.nonce, session.last_rotated, timestamp());
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&state.hmac_key).unwrap();
    mac.update(payload.as_bytes());
    let sig = general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{}.{}", payload, sig)
}

pub fn verify_csrf_token(state: &CaptchaState, token: &str, session: &SessionData) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 2 {
        return false;
    }

    let (payload, sig) = (parts[0], parts[1]);
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&state.hmac_key).unwrap();
    mac.update(payload.as_bytes());
    let expected = general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    let is_valid: bool = sig.as_bytes().ct_eq(expected.as_bytes()).into();

    if !is_valid {
        return false;
    }

    let payload_parts: Vec<&str> = payload.split(':').collect();
    if payload_parts.len() != 3 {
        return false;
    }

    let nonce_match: bool = payload_parts[0]
        .as_bytes()
        .ct_eq(session.nonce.as_bytes())
        .into();
    if !nonce_match {
        return false;
    }

    let token_rotated: u64 = match payload_parts[1].parse() {
        Ok(r) => r,
        Err(_) => return false,
    };

    let rotation_bytes = token_rotated.to_le_bytes();
    let session_bytes = session.last_rotated.to_le_bytes();
    let rotation_match: bool = rotation_bytes.ct_eq(&session_bytes).into();
    if !rotation_match {
        return false;
    }

    let token_timestamp: u64 = match payload_parts[2].parse() {
        Ok(ts) => ts,
        Err(_) => return false,
    };

    let now = timestamp();
    let expiry = token_timestamp.saturating_add(3600);
    let is_valid_time = now <= expiry;

    let valid_bytes = if is_valid_time { [1u8] } else { [0u8] };
    let expected_bytes = [1u8];
    let time_valid: bool = valid_bytes.ct_eq(&expected_bytes).into();

    time_valid
}

pub fn validate_url(url: &str, headers: &HeaderMap) -> bool {
    if url.len() > MAX_URL_LENGTH || url.len() < 10 {
        return false;
    }

    if !url.starts_with("https://") {
        return false;
    }

    if url.contains(['<', '>', '"', '\'', '\0', '\n', '\r', '@']) {
        return false;
    }

    let after_scheme = &url[8..];
    let host_end = after_scheme
        .find('/')
        .or_else(|| after_scheme.find('?'))
        .or_else(|| after_scheme.find('#'))
        .unwrap_or(after_scheme.len());
    let host_part = &after_scheme[..host_end];

    if host_part.is_empty() || host_part.contains('@') || host_part.contains('\\') {
        return false;
    }

    let host = host_part.split(':').next().unwrap_or(host_part);

    if host.parse::<IpAddr>().is_ok() {
        return false;
    }

    if host == "localhost" || host.ends_with(".local") || !host.is_ascii() {
        return false;
    }

    let hostname = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.split(':').next())
        .unwrap_or("localhost");

    if host == hostname || host.ends_with(&format!(".{}", hostname)) {
        return false;
    }

    true
}

pub fn validate_custom_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= MAX_CUSTOM_CODE_LENGTH
        && code.len() != CODE_LENGTH
        && code
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        && !code.starts_with('-')
        && !code.ends_with('-')
}

pub fn calculate_captcha_rounds(has_clearance: bool, has_custom: bool, failures: u32) -> u8 {
    use rand::{rng, RngExt};
    let base = match (has_clearance, has_custom) {
        (false, false) => 2,
        (true, true) => 1,
        (false, true) => 3,
        (true, false) => 0,
    };
    let penalty = if failures > 0 {
        (failures as f32 * rng().random_range(1.2..1.4)).ceil() as u8
    } else {
        0
    };
    (base + penalty).min(5)
}

pub enum CaptchaVerificationResult {
    Success,
    Failed { rounds: u8 },
    InvalidRequest,
}

pub async fn verify_captcha_solution(
    state: &AppState,
    token: &str,
    answers: &[u8],
    request_hash: &str,
    ip: &str,
    base_rounds: u8,
) -> CaptchaVerificationResult {
    use rand::{rng, RngExt};

    let token_key = format!("ct:{}", token);
    let mut conn = state.redis.clone();
    
    let exists: bool = conn.exists(&token_key).await.unwrap_or(false);
    if exists {
        return CaptchaVerificationResult::InvalidRequest;
    }
    
    let _: Result<(), _> = conn.set_ex(&token_key, 1, 600).await;

    if !state.captcha.verify_answer(token, answers, request_hash) {
        let _: Result<(), _> = conn.del(&token_key).await;
        record_captcha_failure(state, ip).await;
        let failures = get_captcha_failures(state, ip).await;
        let penalty = (failures as f32 * rng().random_range(1.0..1.5)).ceil() as u8;
        let rounds = (base_rounds + penalty).min(5);
        return CaptchaVerificationResult::Failed { rounds };
    }

    clear_captcha_failures(state, ip).await;
    CaptchaVerificationResult::Success
}

pub async fn check_and_rotate_session(state: &AppState, mut session: SessionData) -> SessionData {
    if timestamp() - session.last_rotated >= SESSION_ROTATION_INTERVAL {
        let old_nonce = session.nonce.clone();
        session = rotate_session(&session);
        let _ = migrate_session(
            &state.pool,
            &old_nonce,
            &session.nonce,
            session.last_rotated,
        )
        .await;
    }
    session
}

pub async fn authorize_session(
    pool: &sqlx::PgPool,
    session_nonce: &str,
) -> Result<Vec<i64>, ()> {
    authorize(pool, session_nonce).await
}

pub fn validate_link_ids(link_ids: &[i64]) -> bool {
    !link_ids.is_empty()
        && link_ids.len() <= MAX_LINKS_PER_SESSION
        && link_ids.iter().all(|&id| id >= 0)
}

#[tokio::main]
async fn main() {
    let secret_key = std::env::var("RIPPLIT_SECRET_KEY").unwrap_or_else(|_| {
        eprintln!("FATAL: RIPPLIT_SECRET_KEY environment variable not set");
        eprintln!("Set a secure random key: export RIPPLIT_SECRET_KEY=$(openssl rand -base64 32)");
        std::process::exit(1);
    });

    if secret_key.len() < 32 {
        eprintln!("FATAL: RIPPLIT_SECRET_KEY must be at least 32 characters");
        std::process::exit(1);
    }

    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        eprintln!("FATAL: DATABASE_URL environment variable not set");
        std::process::exit(1);
    });

    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| {
        eprintln!("FATAL: REDIS_URL environment variable not set");
        std::process::exit(1);
    });

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");

    init_db(&pool)
        .await
        .expect("Failed to initialize database");

    let redis_client = redis::Client::open(redis_url)
        .expect("Failed to create Redis client");
    let redis = redis::aio::ConnectionManager::new(redis_client)
        .await
        .expect("Failed to connect to Redis");

    let captcha = Arc::new(CaptchaState::new(&secret_key));

    let phishing_filter = Arc::new(tokio::sync::RwLock::new(std::collections::HashSet::new()));
    init_phishing_filter(&phishing_filter).await;
    start_phishing_updater(phishing_filter.clone());

    let state = Arc::new(AppState {
        pool,
        redis,
        captcha,
        phishing_filter,
    });



    let report_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(
            REPORT_QUEUE_INTERVAL,
        ));

        loop {
            interval.tick().await;
            process_report_queue(report_state.clone()).await;
        }
    });

    let app = Router::new()
        .route("/", get(serve_index))
        .route("/privacy", get(serve_privacy))
        .route("/terms", get(serve_terms))
        .route("/report", get(serve_report))
        .route("/report/{token}", get(serve_report_with_token))
        .route(
            "/report/{token}/{review_token}/{action}",
            get(handle_review_action),
        )
        .route("/api/shorten", post(shorten))
        .route("/api/report", post(submit_report))
        .route("/api/links", get(list_links))
        .route("/api/links/delete", post(bulk_delete_links))
        .route("/api/links/edit", post(bulk_edit_links))
        .route("/api/links/{code}", delete(delete_link).post(update_link))
        .route("/api/links/{code}/preview", get(get_link_preview))
        .route(
            "/api/links/{code}/preview/verify",
            post(verify_link_captcha),
        )
        .route("/{code}", get(redirect))
        .fallback(serve_404)
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080")
        .await
        .expect("Failed to bind to port 8080");

    axum::serve(listener, app).await.expect("Server failed");
}
