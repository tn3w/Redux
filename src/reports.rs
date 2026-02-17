use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::Response,
    Json,
};
use base64::{engine::general_purpose, Engine};
use rand::{rng, RngExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::captcha::CaptchaState;
use crate::db::{
    AppState, delete_link_by_code, get_link_url,
    get_pending_report_links, get_report_links_for_code, is_phishing_domain,
    update_report_link_status, clear_report_link_sensitive_data, cleanup_old_reports,
};
use crate::handlers::{
    build_html_response, generate_captcha_challenge, json_error, validate_content_type,
    verify_captcha_token, MAX_BULK_OPERATIONS, MAX_REQUESTS_PER_MINUTE, MAX_CAPTCHA_ROUNDS,
};
use crate::Link;
use crate::{
    check_and_rotate_session, check_captcha_rate_limit, check_rate_limit, csrf_cookie,
    generate_csrf_token, get_captcha_failures, get_client_ip, get_session, random_string,
    session_cookie, timestamp, MAX_CUSTOM_CODE_LENGTH,
};

pub const REPORT_QUEUE_INTERVAL: u64 = 30;
pub const REPORT_AUTO_CLOSE_DAYS: i64 = 30;

#[derive(Deserialize)]
pub struct ReportLinkItem {
    pub code: String,
    pub token: Option<String>,
}

#[derive(Deserialize)]
pub struct ReportRequest {
    pub links: Vec<ReportLinkItem>,
    pub reason: String,
    pub description: String,
    pub captcha_token: Option<String>,
    pub captcha_answers: Option<Vec<u8>>,
}

#[derive(Serialize)]
pub struct ReportLinkStatus {
    pub code: String,
    pub status: String,
    pub link_url: Option<String>,
    pub encrypted: bool,
}

#[derive(Serialize)]
pub struct ReportStatus {
    pub report_token: String,
    pub reason: String,
    pub created_at: i64,
    pub links: Vec<ReportLinkStatus>,
}

fn generate_review_token(report_token: &str, secret_key: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(secret_key.as_bytes());
    hasher.update(report_token.as_bytes());
    hasher.update(b"review_token");
    let result = hasher.finalize();
    hex::encode(&result[..16])
}

async fn send_discord_webhook(
    report_token: &str,
    reason: &str,
    description: &str,
    link_count: usize,
    review_token: &str,
    link_urls: &[String],
) {
    let webhook_url = match std::env::var("DISCORD_WEBHOOK_URL") {
        Ok(url) if !url.is_empty() => url,
        _ => return,
    };

    let base_url =
        std::env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());

    let reason_display = match reason {
        "malware" => "Malware / Phishing",
        "spam" => "Spam",
        "csam" => "CSAM",
        "violence" => "Violence / Gore",
        "harassment" => "Harassment",
        "copyright" => "Copyright",
        _ => reason,
    };

    let desc = if description.len() > 150 {
        format!("{}...", &description[..150])
    } else {
        description.to_string()
    };

    let urls_text = if link_urls.is_empty() {
        String::new()
    } else {
        let defanged: Vec<String> = link_urls
            .iter()
            .take(3)
            .map(|url| url.replace('.', "[.]"))
            .collect();

        if link_urls.len() <= 3 {
            format!("\n**URLs:** {}", defanged.join(", "))
        } else {
            format!(
                "\n**URLs:** {} and {} more",
                defanged.join(", "),
                link_urls.len() - 3
            )
        }
    };

    let content = format!(
        "🚨 **Report Requires Review**\n\n\
        **Reason:** {}\n\
        **Links:** {}{}\n\
        **Description:** {}\n\n\
        **View:** <{}/report/{}>\n\
        **Actions:** [Dismiss](<{}/report/{}/{}/dismiss>) | [Remove](<{}/report/{}/{}/remove>)",
        reason_display,
        link_count,
        urls_text,
        desc,
        base_url,
        report_token,
        base_url,
        report_token,
        review_token,
        base_url,
        report_token,
        review_token
    );

    let payload = serde_json::json!({ "content": content });

    tokio::task::spawn_blocking(move || {
        let _ = ureq::post(&webhook_url).send_json(payload);
    });
}

pub async fn process_report_queue(state: Arc<AppState>) {
    let report_links = match get_pending_report_links(&state.pool).await {
        Ok(r) => r,
        Err(_) => return,
    };

    let mut notified_reports = std::collections::HashSet::new();

    for (report_link_id, report_token, code, token) in report_links {
        let link_data = match get_link_url(&state.pool, &code).await {
            Ok(Some(data)) => data,
            Ok(None) => {
                let _ = update_report_link_status(
                    &state.pool,
                    report_link_id,
                    "automated_removed",
                )
                .await;
                let _ =
                    clear_report_link_sensitive_data(&state.pool, report_link_id).await;
                continue;
            }
            Err(_) => continue,
        };

        let (url, encrypted) = link_data;

        let actual_url = if encrypted {
            if let Some(ref t) = token {
                match decrypt_url(&url, t) {
                    Ok(decrypted) => decrypted,
                    Err(_) => {
                        let _ = update_report_link_status(
                            &state.pool,
                            report_link_id,
                            "investigating",
                        )
                        .await;
                        continue;
                    }
                }
            } else {
                let _ = update_report_link_status(
                    &state.pool,
                    report_link_id,
                    "investigating",
                )
                .await;
                continue;
            }
        } else {
            url.clone()
        };

        if is_phishing_domain(&state.phishing_filter, &actual_url).await {
            let _ = delete_link_by_code(&state.pool, &code).await;

            if let Ok(report_links) = get_report_links_for_code(&state.pool, &code).await
            {
                for (rlid, _) in report_links {
                    let _ = update_report_link_status(
                        &state.pool,
                        rlid,
                        "automated_removed",
                    )
                    .await;
                    let _ = clear_report_link_sensitive_data(&state.pool, rlid).await;
                }
            }
            continue;
        }

        if let Ok(report_links) = get_report_links_for_code(&state.pool, &code).await {
            let mut needs_review = false;
            for (rlid, _report_token_for_link) in report_links {
                let current_status =
                    sqlx::query_as::<_, (String,)>("SELECT status FROM report_links WHERE id = $1")
                        .bind(rlid)
                        .fetch_optional(&state.pool)
                        .await
                        .ok()
                        .flatten()
                        .map(|(s,)| s);

                if current_status.as_deref() == Some("automated") {
                    needs_review = true;
                }

                let _ =
                    update_report_link_status(&state.pool, rlid, "investigating").await;
            }

            if needs_review && !notified_reports.contains(&report_token) {
                notified_reports.insert(report_token.clone());

                if let Ok(Some((report_token_str, reason, description))) = sqlx::query_as::<
                    _,
                    (String, String, String),
                >(
                    "SELECT report_token, reason, description FROM reports WHERE report_token = $1",
                )
                .bind(&report_token)
                .fetch_optional(&state.pool)
                .await
                {
                    let secret_key = std::env::var("RIPPLIT_SECRET_KEY").unwrap_or_default();
                    let review_token = generate_review_token(&report_token_str, &secret_key);

                    let link_count = sqlx::query_as::<_, (i64,)>(
                        "SELECT COUNT(*) FROM report_links WHERE report_token = $1",
                    )
                    .bind(&report_token_str)
                    .fetch_optional(&state.pool)
                    .await
                    .ok()
                    .flatten()
                    .map(|(c,)| c as usize)
                    .unwrap_or(0);

                    let link_urls: Vec<String> =
                        sqlx::query_as::<_, (String, Option<String>, bool)>(
                            "SELECT l.original_url, rl.token, l.encrypted FROM report_links rl \
                         JOIN links l ON rl.code = l.code WHERE rl.report_token = $1",
                        )
                        .bind(&report_token_str)
                        .fetch_all(&state.pool)
                        .await
                        .unwrap_or_default()
                        .into_iter()
                        .filter_map(|(url, token, encrypted)| {
                            if encrypted {
                                token.and_then(|t| decrypt_url(&url, &t).ok())
                            } else {
                                Some(url)
                            }
                        })
                        .collect();

                    let unique_urls: Vec<String> = link_urls
                        .into_iter()
                        .collect::<std::collections::HashSet<_>>()
                        .into_iter()
                        .collect();

                    send_discord_webhook(
                        &report_token_str,
                        &reason,
                        &description,
                        link_count,
                        &review_token,
                        &unique_urls,
                    )
                    .await;
                }
            }
        }
    }

    let _ = cleanup_old_reports(&state.pool, REPORT_AUTO_CLOSE_DAYS).await;
}

pub fn decrypt_url(encrypted: &str, token: &str) -> Result<String, ()> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;

    let padded_token = if token.len() < 16 {
        format!("{:_<16}", token)
    } else {
        token.to_string()
    };

    let mut key_bytes = [0u8; 32];
    pbkdf2_hmac::<Sha256>(padded_token.as_bytes(), b"Ripplit", 100000, &mut key_bytes);

    let encrypted_normalized = encrypted.replace('-', "+").replace('_', "/");
    let padding_needed = (4 - (encrypted_normalized.len() % 4)) % 4;
    let encrypted_padded = if padding_needed > 0 {
        format!("{}{}", encrypted_normalized, "=".repeat(padding_needed))
    } else {
        encrypted_normalized
    };

    let data = general_purpose::STANDARD
        .decode(&encrypted_padded)
        .map_err(|_| ())?;

    if data.len() < 12 {
        return Err(());
    }

    let nonce_bytes = &data[0..12];
    let ciphertext = &data[12..];

    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|_| ())?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| ())?;

    String::from_utf8(plaintext).map_err(|_| ())
}

pub async fn serve_report(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    serve_report_internal(State(state), headers, None).await
}

pub async fn serve_report_with_token(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Response {
    let initial_data = get_report_data(&state, &token).await;
    serve_report_internal(State(state), headers, initial_data).await
}

async fn serve_report_internal(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    initial_data: Option<ReportStatus>,
) -> Response {
    let html = tokio::fs::read_to_string("build/report.html")
        .await
        .unwrap_or_default();
    let session = check_and_rotate_session(&state, get_session(&state.captcha, &headers)).await;
    let csrf_token = generate_csrf_token(&state.captcha, &session);

    let html_with_data = if let Some(data) = initial_data {
        let data_json = serde_json::to_string(&data).unwrap_or_default();
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

pub async fn submit_report(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ReportRequest>,
) -> Result<Response, Response> {
    validate_content_type(&headers).map_err(|e| *e)?;

    let ip = get_client_ip(&headers)
        .ok_or_else(|| json_error(StatusCode::BAD_REQUEST, "Invalid request"))?;

    check_rate_limit(&state, &ip, MAX_REQUESTS_PER_MINUTE)
        .await
        .map_err(|_| json_error(StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded"))?;

    if req.links.is_empty() || req.links.len() > MAX_BULK_OPERATIONS {
        return Err(json_error(StatusCode::BAD_REQUEST, "Invalid links count"));
    }

    if req.description.trim().is_empty() || req.description.len() > 2000 {
        return Err(json_error(StatusCode::BAD_REQUEST, "Invalid description"));
    }

    let valid_reasons = [
        "malware",
        "spam",
        "csam",
        "violence",
        "harassment",
        "copyright",
        "other",
    ];
    if !valid_reasons.contains(&req.reason.as_str()) {
        return Err(json_error(StatusCode::BAD_REQUEST, "Invalid reason"));
    }

    let mut validated_links = Vec::new();
    for link_item in &req.links {
        if link_item.code.is_empty() || link_item.code.len() > MAX_CUSTOM_CODE_LENGTH {
            return Err(json_error(StatusCode::BAD_REQUEST, "Invalid code"));
        }

        let link = sqlx::query_as::<_, Link>(
            "SELECT id, code, original_url, encrypted, created_at, clicks, \
             signature, require_captcha, show_page FROM links WHERE code = $1",
        )
        .bind(&link_item.code)
        .fetch_optional(&state.pool)
        .await
        .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?
        .ok_or_else(|| {
            json_error(
                StatusCode::NOT_FOUND,
                &format!("Link not found: {}", link_item.code),
            )
        })?;

        if link.encrypted {
            if let Some(t) = &link_item.token {
                if t.is_empty() || t.len() > 256 {
                    return Err(json_error(StatusCode::BAD_REQUEST, "Invalid token"));
                }
                decrypt_url(&link.original_url, t).map_err(|_| {
                    json_error(
                        StatusCode::BAD_REQUEST,
                        &format!("Decryption failed for: {}", link_item.code),
                    )
                })?;
            } else {
                return Err(json_error(
                    StatusCode::BAD_REQUEST,
                    &format!("Token required for encrypted link: {}", link_item.code),
                ));
            }
        }

        validated_links.push((link_item.code.clone(), link_item.token.clone()));
    }

    let failures = get_captcha_failures(&state, &ip).await;
    let base_rounds = 3u8;
    let penalty = if failures > 0 {
        (failures as f32 * rng().random_range(1.0..1.5)).ceil() as u8
    } else {
        0
    };
    let rounds = (base_rounds + penalty).min(MAX_CAPTCHA_ROUNDS);

    check_captcha_rate_limit(&state, &ip)
        .await
        .map_err(|_| json_error(StatusCode::TOO_MANY_REQUESTS, "Too many captcha requests"))?;

    let request_hash = CaptchaState::hash_request(
        &format!("{}{}", validated_links.len(), req.reason),
        false,
        &None,
        &None,
    );

    if let (Some(token), Some(answers)) = (&req.captcha_token, &req.captcha_answers) {
        verify_captcha_token(&state, token, answers, &request_hash, &ip, base_rounds).await?;
    } else {
        return Ok(generate_captcha_challenge(&state, rounds, &request_hash));
    }

    let report_token = random_string(32);

    sqlx::query(
        "INSERT INTO reports (report_token, reason, description, created_at) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(&report_token)
    .bind(&req.reason)
    .bind(&req.description)
    .bind(timestamp() as i64)
    .execute(&state.pool)
    .await
    .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;

    for (code, token) in validated_links {
        sqlx::query(
            "INSERT INTO report_links (report_token, code, token, status) \
             VALUES ($1, $2, $3, 'automated')",
        )
        .bind(&report_token)
        .bind(&code)
        .bind(&token)
        .execute(&state.pool)
        .await
        .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(report_token.into())
        .unwrap())
}

async fn get_report_data(state: &AppState, token: &str) -> Option<ReportStatus> {
    if token.len() != 32 || !token.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }

    let report = sqlx::query_as::<_, (String, String, i64)>(
        "SELECT report_token, reason, created_at FROM reports WHERE report_token = $1",
    )
    .bind(token)
    .fetch_optional(&state.pool)
    .await
    .ok()??;

    let report_links = sqlx::query_as::<_, (String, Option<String>, String)>(
        "SELECT code, token, status FROM report_links WHERE report_token = $1",
    )
    .bind(token)
    .fetch_all(&state.pool)
    .await
    .ok()?;

    let mut links = Vec::new();
    for (code, decryption_token, status) in report_links {
        let link_data = sqlx::query_as::<_, (String, bool)>(
            "SELECT original_url, encrypted FROM links WHERE code = $1",
        )
        .bind(&code)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten();

        let (link_url, encrypted) = if let Some((url, enc)) = link_data {
            let actual_url = if enc {
                if let Some(token) = decryption_token.as_ref() {
                    match decrypt_url(&url, token) {
                        Ok(decrypted) => Some(decrypted),
                        Err(_) => Some("[Encrypted - decryption failed]".to_string()),
                    }
                } else {
                    Some("[Encrypted - no decryption key]".to_string())
                }
            } else {
                Some(url)
            };
            (actual_url, enc)
        } else {
            (None, false)
        };

        links.push(ReportLinkStatus {
            code,
            status,
            link_url,
            encrypted,
        });
    }

    Some(ReportStatus {
        report_token: report.0,
        reason: report.1,
        created_at: report.2,
        links,
    })
}

pub async fn handle_review_action(
    State(state): State<Arc<AppState>>,
    Path((report_token, review_token, action)): Path<(String, String, String)>,
) -> Response {
    if report_token.len() != 32 || !report_token.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body("Invalid report token".into())
            .unwrap();
    }

    if review_token.len() != 32 || !review_token.chars().all(|c| c.is_ascii_hexdigit()) {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body("Invalid review token".into())
            .unwrap();
    }

    if action != "dismiss" && action != "remove" {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body("Invalid action".into())
            .unwrap();
    }

    let secret_key = std::env::var("RIPPLIT_SECRET_KEY").unwrap_or_default();
    let expected_token = generate_review_token(&report_token, &secret_key);

    if review_token != expected_token {
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body("Invalid review token".into())
            .unwrap();
    }

    let report_exists =
        sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM reports WHERE report_token = $1")
            .bind(&report_token)
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten()
            .map(|(count,)| count > 0)
            .unwrap_or(false);

    if !report_exists {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body("Report not found".into())
            .unwrap();
    }

    let report_links = sqlx::query_as::<_, (i64, String)>(
        "SELECT id, code FROM report_links WHERE report_token = $1",
    )
    .bind(&report_token)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let (title, icon, message) = if action == "dismiss" {
        for (rlid, _) in report_links {
            let _ = update_report_link_status(&state.pool, rlid, "dismissed").await;
            let _ = clear_report_link_sensitive_data(&state.pool, rlid).await;
        }
        (
            "Report Dismissed".to_string(),
            "✓".to_string(),
            "The report has been dismissed and marked as not requiring action.".to_string(),
        )
    } else {
        for (rlid, code) in &report_links {
            let _ = delete_link_by_code(&state.pool, code).await;
            let _ =
                update_report_link_status(&state.pool, *rlid, "investigating_removed")
                    .await;
            let _ = clear_report_link_sensitive_data(&state.pool, *rlid).await;
        }
        let count = report_links.len();
        (
            "Links Removed".to_string(),
            "✓".to_string(),
            format!("{} link(s) have been removed from the system.", count),
        )
    };

    let html = tokio::fs::read_to_string("build/report_action.html")
        .await
        .unwrap_or_default()
        .replace("{{title}}", &title)
        .replace("{{icon}}", &icon)
        .replace("{{message}}", &message)
        .replace("{{report_token}}", &report_token);

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(html.into())
        .unwrap()
}
