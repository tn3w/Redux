use sqlx::{Row, PgPool};
use std::collections::HashSet;
use std::io::Read;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::captcha::CaptchaState;
use crate::{random_string, timestamp, Link, BulkEditItem};

pub const MAX_LINKS_PER_SESSION: usize = 1000;
pub const MAX_BULK_OPERATIONS: usize = 100;
pub const RATE_WINDOW: u64 = 60;

const BLOCKLIST_URLS: &[&str] = &[
    "https://raw.githubusercontent.com/Zaczero/pihole-phishtank/main/hosts.txt",
    "https://phishing.army/download/phishing_army_blocklist.txt",
    "https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt",
];
const BLOCKLIST_PATH: &str = "phishing_domains.json";
const UPDATE_INTERVAL: u64 = 86400;

pub struct AppState {
    pub pool: PgPool,
    pub redis: redis::aio::ConnectionManager,
    pub captcha: Arc<CaptchaState>,
    pub phishing_filter: Arc<RwLock<HashSet<String>>>,
}

pub async fn init_db(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS links (
            id BIGSERIAL PRIMARY KEY,
            code TEXT UNIQUE NOT NULL,
            original_url TEXT NOT NULL,
            encrypted BOOLEAN DEFAULT false,
            created_at BIGINT NOT NULL,
            clicks BIGINT DEFAULT 0,
            signature TEXT,
            require_captcha BOOLEAN DEFAULT false,
            show_page BOOLEAN DEFAULT false
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            link_ids TEXT NOT NULL DEFAULT '',
            last_rotated BIGINT NOT NULL DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS reports (
            id BIGSERIAL PRIMARY KEY,
            report_token TEXT UNIQUE NOT NULL,
            reason TEXT NOT NULL,
            description TEXT NOT NULL,
            created_at BIGINT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS report_links (
            id BIGSERIAL PRIMARY KEY,
            report_token TEXT NOT NULL,
            code TEXT NOT NULL,
            token TEXT,
            status TEXT DEFAULT 'automated',
            processed_at BIGINT,
            FOREIGN KEY (report_token) REFERENCES reports(report_token)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_sessions_last_rotated \
         ON sessions(last_rotated)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_reports_created \
         ON reports(created_at)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_report_links_status \
         ON report_links(status)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_report_links_token \
         ON report_links(report_token)",
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn authorize(pool: &PgPool, session_id: &str) -> Result<Vec<i64>, ()> {
    if session_id.is_empty() || session_id.len() > 64 {
        return Err(());
    }

    sqlx::query("SELECT link_ids FROM sessions WHERE session_id = $1")
        .bind(session_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .map(|r| r.get::<String, _>(0))
        .filter(|ids| !ids.is_empty())
        .map(|ids| ids.split(',').filter_map(|s| s.parse().ok()).collect())
        .ok_or(())
}

pub async fn generate_unique_code(pool: &PgPool, length: usize) -> Result<String, ()> {
    for _ in 0..10 {
        let code = random_string(length);
        if sqlx::query("SELECT 1 FROM links WHERE code = $1")
            .bind(&code)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten()
            .is_none()
        {
            return Ok(code);
        }
    }
    Err(())
}

pub async fn add_link_to_session(
    pool: &PgPool,
    session_id: &str,
    link_id: i64,
) -> Result<(), sqlx::Error> {
    let row = sqlx::query("SELECT link_ids FROM sessions WHERE session_id = $1")
        .bind(session_id)
        .fetch_optional(pool)
        .await?;

    if let Some(row) = row {
        let link_ids: String = row.get(0);
        let count = if link_ids.is_empty() {
            0
        } else {
            link_ids.split(',').count()
        };

        if count >= MAX_LINKS_PER_SESSION {
            return Err(sqlx::Error::Protocol("Session link limit exceeded".into()));
        }
    }

    sqlx::query(
        "UPDATE sessions SET link_ids = 
         CASE 
             WHEN link_ids = '' THEN CAST($1 AS TEXT)
             ELSE link_ids || ',' || CAST($2 AS TEXT)
         END
         WHERE session_id = $3",
    )
    .bind(link_id)
    .bind(link_id)
    .bind(session_id)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn cleanup_session_if_empty(
    pool: &PgPool,
    session_id: &str,
) -> Result<(), sqlx::Error> {
    let row = sqlx::query("SELECT link_ids FROM sessions WHERE session_id = $1")
        .bind(session_id)
        .fetch_optional(pool)
        .await?;

    if let Some(row) = row {
        let link_ids: String = row.get(0);
        let ids: Vec<i64> = link_ids.split(',').filter_map(|s| s.parse().ok()).collect();

        if ids.is_empty() {
            sqlx::query("DELETE FROM sessions WHERE session_id = $1")
                .bind(session_id)
                .execute(pool)
                .await?;
            return Ok(());
        }

        if ids.len() > MAX_LINKS_PER_SESSION {
            return Ok(());
        }

        let count = count_existing_links(pool, &ids).await?;

        if count == 0 {
            sqlx::query("DELETE FROM sessions WHERE session_id = $1")
                .bind(session_id)
                .execute(pool)
                .await?;
        }
    }

    Ok(())
}

pub async fn count_existing_links(pool: &PgPool, ids: &[i64]) -> Result<i64, sqlx::Error> {
    if ids.is_empty() {
        return Ok(0);
    }

    if ids.len() > MAX_LINKS_PER_SESSION {
        return Ok(0);
    }

    let mut query_builder = sqlx::QueryBuilder::new("SELECT COUNT(*) FROM links WHERE id IN (");

    let mut separated = query_builder.separated(", ");
    for id in ids {
        separated.push_bind(id);
    }
    separated.push_unseparated(")");

    let query = query_builder.build_query_scalar::<i64>();
    query.fetch_one(pool).await
}

pub async fn fetch_links_by_ids(
    pool: &PgPool,
    ids: &[i64],
) -> Result<Vec<Link>, sqlx::Error> {
    if ids.is_empty() || ids.len() > MAX_LINKS_PER_SESSION {
        return Ok(vec![]);
    }

    let mut query_builder = sqlx::QueryBuilder::new(
        "SELECT id, code, original_url, encrypted, created_at, clicks, signature, \
         require_captcha, show_page FROM links WHERE id IN (",
    );

    let mut separated = query_builder.separated(", ");
    for id in ids {
        separated.push_bind(id);
    }
    separated.push_unseparated(") ORDER BY created_at DESC");

    let query = query_builder.build_query_as::<Link>();
    query.fetch_all(pool).await
}

pub async fn migrate_session(
    pool: &PgPool,
    old_nonce: &str,
    new_nonce: &str,
    new_last_rotated: u64,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;

    let row = sqlx::query("SELECT link_ids FROM sessions WHERE session_id = $1")
        .bind(old_nonce)
        .fetch_optional(&mut *tx)
        .await?;

    if let Some(row) = row {
        let link_ids: String = row.get(0);

        sqlx::query(
            "INSERT INTO sessions (session_id, link_ids, last_rotated) \
             VALUES ($1, $2, $3)",
        )
        .bind(new_nonce)
        .bind(&link_ids)
        .bind(new_last_rotated as i64)
        .execute(&mut *tx)
        .await?;

        sqlx::query("DELETE FROM sessions WHERE session_id = $1")
            .bind(old_nonce)
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;
    Ok(())
}

pub async fn delete_links_by_codes(
    pool: &PgPool,
    codes: &[String],
    link_ids: &[i64],
) -> Result<u64, sqlx::Error> {
    if codes.is_empty()
        || link_ids.is_empty()
        || codes.len() > MAX_BULK_OPERATIONS
        || link_ids.len() > MAX_LINKS_PER_SESSION
    {
        return Ok(0);
    }

    for id in link_ids {
        if *id < 0 {
            return Ok(0);
        }
    }

    let mut tx = pool.begin().await?;
    let mut total = 0u64;

    for code in codes {
        let mut query_builder = sqlx::QueryBuilder::new("DELETE FROM links WHERE code = ");
        query_builder.push_bind(code);
        query_builder.push(" AND id IN (");

        let mut separated = query_builder.separated(", ");
        for id in link_ids {
            separated.push_bind(id);
        }
        separated.push_unseparated(")");

        if let Ok(result) = query_builder.build().execute(&mut *tx).await {
            total += result.rows_affected();
        }
    }

    tx.commit().await?;
    Ok(total)
}

pub async fn update_links_by_edits(
    pool: &PgPool,
    edits: &[BulkEditItem],
    link_ids: &[i64],
) -> Result<u64, sqlx::Error> {
    if edits.is_empty()
        || link_ids.is_empty()
        || edits.len() > MAX_BULK_OPERATIONS
        || link_ids.len() > MAX_LINKS_PER_SESSION
    {
        return Ok(0);
    }

    for id in link_ids {
        if *id < 0 {
            return Ok(0);
        }
    }

    let mut tx = pool.begin().await?;
    let mut total = 0u64;

    for edit in edits {
        let mut query_builder = sqlx::QueryBuilder::new("UPDATE links SET original_url = ");
        query_builder.push_bind(&edit.url);
        query_builder.push(", signature = ");
        query_builder.push_bind(&edit.signature);
        query_builder.push(" WHERE code = ");
        query_builder.push_bind(&edit.code);
        query_builder.push(" AND id IN (");

        let mut separated = query_builder.separated(", ");
        for id in link_ids {
            separated.push_bind(id);
        }
        separated.push_unseparated(")");

        if let Ok(result) = query_builder.build().execute(&mut *tx).await {
            total += result.rows_affected();
        }
    }

    tx.commit().await?;
    Ok(total)
}



pub async fn init_phishing_filter(filter: &RwLock<HashSet<String>>) {
    if let Ok(data) = tokio::fs::read_to_string(BLOCKLIST_PATH).await {
        if let Ok(domains) = serde_json::from_str::<Vec<String>>(&data) {
            *filter.write().await = domains.into_iter().collect();
        }
    }

    if filter.read().await.is_empty() {
        update_phishing_filter(filter).await;
    }
}

pub async fn update_phishing_filter(filter: &RwLock<HashSet<String>>) {
    let mut all_domains = HashSet::new();

    for url in BLOCKLIST_URLS {
        if let Ok(Some(body)) = tokio::task::spawn_blocking({
            let url = url.to_string();
            move || -> Option<String> {
                let mut response = ureq::get(&url).call().ok()?;
                let mut body = String::new();
                response
                    .body_mut()
                    .as_reader()
                    .read_to_string(&mut body)
                    .ok()?;
                Some(body)
            }
        })
        .await
        {
            for line in body.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('#') || trimmed.starts_with('!') {
                    continue;
                }
                if let Some(domain) = parse_filter_line(line) {
                    all_domains.insert(domain);
                }
            }
        }
    }

    if !all_domains.is_empty() {
        *filter.write().await = all_domains.clone();

        let domains_vec: Vec<String> = all_domains.into_iter().collect();
        if let Ok(json) = serde_json::to_string(&domains_vec) {
            let _ = tokio::fs::write(BLOCKLIST_PATH, json).await;
        }
    }
}

fn parse_filter_line(line: &str) -> Option<String> {
    let trimmed = line.trim();

    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
        return None;
    }

    let mut entry = trimmed.to_string();

    if entry.starts_with("||") {
        entry = entry[2..].to_string();
    }

    if let Some(pos) = entry.find('^') {
        entry = entry[..pos].to_string();
    }

    if let Some(pos) = entry.find('$') {
        entry = entry[..pos].to_string();
    }

    entry = entry.trim().to_lowercase();

    let domain_part = if let Some(pos) = entry.find('/') {
        &entry[..pos]
    } else {
        &entry
    };

    if domain_part.contains('.') && !domain_part.is_empty() {
        Some(entry)
    } else {
        None
    }
}

pub fn start_phishing_updater(filter: Arc<RwLock<HashSet<String>>>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(UPDATE_INTERVAL));

        loop {
            interval.tick().await;
            update_phishing_filter(&filter).await;
        }
    });
}

pub async fn is_phishing_domain(filter: &RwLock<HashSet<String>>, url: &str) -> bool {
    let domain = extract_domain(url);
    if domain.is_empty() {
        return false;
    }

    let path = extract_domain_and_path(url);
    let entries = filter.read().await;

    if entries.contains(&domain) || entries.contains(&path) {
        return true;
    }

    for entry in entries.iter() {
        if entry.contains('/') {
            if path.starts_with(entry) {
                return true;
            }
            if entry.starts_with(&path) {
                return true;
            }
        }
    }

    let parts: Vec<&str> = domain.split('.').collect();
    for i in 1..parts.len() {
        let parent = parts[i..].join(".");
        if entries.contains(&parent) {
            return true;
        }
    }

    false
}

fn extract_domain(url: &str) -> String {
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);

    let host_end = after_scheme
        .find('/')
        .or_else(|| after_scheme.find('?'))
        .or_else(|| after_scheme.find('#'))
        .unwrap_or(after_scheme.len());

    let host_part = &after_scheme[..host_end];
    let host = host_part.split(':').next().unwrap_or(host_part);

    host.to_lowercase()
}

fn extract_domain_and_path(url: &str) -> String {
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);

    let path_end = after_scheme
        .find('?')
        .or_else(|| after_scheme.find('#'))
        .unwrap_or(after_scheme.len());

    let domain_and_path = &after_scheme[..path_end];
    let without_port = domain_and_path.split(':').next().unwrap_or(domain_and_path);

    without_port.to_lowercase()
}

pub async fn get_pending_report_links(
    pool: &PgPool,
) -> Result<Vec<(i64, String, String, Option<String>)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, report_token, code, token FROM report_links \
         WHERE status = 'automated' ORDER BY id ASC LIMIT 100",
    )
    .fetch_all(pool)
    .await
}

pub async fn update_report_link_status(
    pool: &PgPool,
    report_link_id: i64,
    status: &str,
) -> Result<(), sqlx::Error> {
    let now = timestamp() as i64;
    sqlx::query("UPDATE report_links SET status = $1, processed_at = $2 WHERE id = $3")
        .bind(status)
        .bind(now)
        .bind(report_link_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn clear_report_link_sensitive_data(
    pool: &PgPool,
    report_link_id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE report_links SET token = NULL WHERE id = $1")
        .bind(report_link_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn get_report_links_for_code(
    pool: &PgPool,
    code: &str,
) -> Result<Vec<(i64, String)>, sqlx::Error> {
    sqlx::query_as("SELECT id, status FROM report_links WHERE code = $1")
        .bind(code)
        .fetch_all(pool)
        .await
}

pub async fn delete_link_by_code(pool: &PgPool, code: &str) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM links WHERE code = $1")
        .bind(code)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

pub async fn get_link_url(
    pool: &PgPool,
    code: &str,
) -> Result<Option<(String, bool)>, sqlx::Error> {
    sqlx::query_as("SELECT original_url, encrypted FROM links WHERE code = $1")
        .bind(code)
        .fetch_optional(pool)
        .await
}

pub async fn cleanup_old_reports(pool: &PgPool, days: i64) -> Result<(), sqlx::Error> {
    let cutoff = timestamp() as i64 - (days * 86400);

    let report_tokens: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT r.report_token FROM reports r \
         JOIN report_links rl ON r.report_token = rl.report_token \
         WHERE r.created_at < $1 \
         AND rl.status IN ('automated_removed', 'investigating_removed', 'dismissed')"
    )
    .bind(cutoff)
    .fetch_all(pool)
    .await?;

    for report_token in report_tokens {
        sqlx::query("DELETE FROM report_links WHERE report_token = $1")
            .bind(&report_token)
            .execute(pool)
            .await?;

        sqlx::query("DELETE FROM reports WHERE report_token = $1")
            .bind(&report_token)
            .execute(pool)
            .await?;
    }

    Ok(())
}
