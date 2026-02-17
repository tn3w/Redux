use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose, Engine};
use hmac::{Hmac, Mac};
use image::{ImageBuffer, Rgba, RgbaImage};
use rand::prelude::*;
use rand::{rng, RngExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Cursor;

const ICON_SIZE: u32 = 22;
const IMAGE_SIZE: u32 = 200;
const REFERENCE_SIZE: u32 = 133;
const CUP_WIDTH: i32 = 32;
const CUP_HEIGHT: i32 = 40;
const TOKEN_TTL: u64 = 300;
const ICON_CACHE_FILE: &str = "captcha_icons.cache";
const BRIGHTNESS_LEVELS: [f32; 11] = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0];
const NOISE_DENSITY: f32 = 0.015;
const DISTORTION_STRENGTH: f32 = 3.0;

type HmacSha256 = Hmac<Sha256>;
type IconCache = HashMap<(String, u8, u32), Vec<u8>>;

#[derive(Clone, Serialize, Deserialize)]
pub struct Challenge {
    correct: Vec<u8>,
    icon: String,
    brightness: f32,
    pub rounds: Vec<u8>,
}

#[derive(Serialize)]
pub struct CaptchaResponse {
    pub token: String,
    pub image: String,
    pub rounds: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct CacheData {
    icons: IconCache,
    names: Vec<String>,
}

pub struct CaptchaState {
    cache: IconCache,
    icons: Vec<String>,
    cipher: Aes256Gcm,
    pub hmac_key: [u8; 32],
}

impl CaptchaState {
    pub fn new(secret: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        hasher.update(b"captcha-aes");
        let aes_key = hasher.finalize();

        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        hasher.update(b"captcha-hmac");
        let hmac_key: [u8; 32] = hasher.finalize().into();

        let (cache, icons) = Self::load_cache().unwrap_or_else(|| {
            eprintln!("Warning: Icon cache not found, building from SVGs...");
            Self::build_cache()
        });

        Self {
            cache,
            icons,
            cipher: Aes256Gcm::new_from_slice(&aes_key).unwrap(),
            hmac_key,
        }
    }

    fn load_cache() -> Option<(IconCache, Vec<String>)> {
        let data = std::fs::read(ICON_CACHE_FILE).ok()?;
        let cache_data: CacheData = deserialize_bincode(&data).ok()?;
        Some((cache_data.icons, cache_data.names))
    }

    fn build_cache() -> (IconCache, Vec<String>) {
        let icon_names: Vec<String> = std::fs::read_dir("icons/fontawesome")
            .ok()
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().is_some_and(|x| x == "svg"))
                    .filter_map(|e| e.path().file_stem().map(|s| s.to_string_lossy().into()))
                    .collect()
            })
            .unwrap_or_default();

        let mut cache = HashMap::new();

        for icon_name in &icon_names {
            let svg_path = format!("icons/fontawesome/{}.svg", icon_name);
            let svg_content = match std::fs::read_to_string(&svg_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            for &brightness in &BRIGHTNESS_LEVELS {
                let bright_key = (brightness * 10.0).round() as u8;
                let key = (icon_name.clone(), bright_key, ICON_SIZE);

                if let Some(img) = Self::render_svg(&svg_content, brightness, ICON_SIZE) {
                    cache.insert(key, img.into_raw());
                }
            }
        }

        let cache_data = CacheData {
            icons: cache.clone(),
            names: icon_names.clone(),
        };

        if let Ok(data) = serialize_bincode(&cache_data) {
            std::fs::write(ICON_CACHE_FILE, data).ok();
        }

        (cache, icon_names)
    }

    fn render_svg(svg_content: &str, brightness: f32, size: u32) -> Option<RgbaImage> {
        let intensity = (30.0 + brightness * 210.0) as u8;
        let color = format!("#{:02x}{:02x}{:02x}", intensity, intensity, intensity);

        let svg = if svg_content.contains("fill=\"") {
            let mut result = svg_content.to_string();
            while let Some(start) = result.find("fill=\"") {
                if let Some(end) = result[start + 6..].find('"') {
                    result.replace_range(start..start + 7 + end, &format!("fill=\"{}\"", color));
                } else {
                    break;
                }
            }
            result
        } else {
            svg_content.replace("<path ", &format!("<path fill=\"{}\" ", color))
        };

        let tree = resvg::usvg::Tree::from_str(&svg, &resvg::usvg::Options::default()).ok()?;
        let mut pixmap = resvg::tiny_skia::Pixmap::new(size, size)?;

        let tree_size = tree.size();
        let scale = (size as f32 / tree_size.width()).min(size as f32 / tree_size.height());
        let offset_x = (size as f32 - tree_size.width() * scale) / 2.0;
        let offset_y = (size as f32 - tree_size.height() * scale) / 2.0;

        let transform =
            resvg::usvg::Transform::from_scale(scale, scale).post_translate(offset_x, offset_y);
        resvg::render(&tree, transform, &mut pixmap.as_mut());

        let data = pixmap.data();
        let mut img = RgbaImage::new(size, size);
        for (i, pixel) in img.pixels_mut().enumerate() {
            let idx = i * 4;
            *pixel = Rgba([data[idx], data[idx + 1], data[idx + 2], data[idx + 3]]);
        }
        Some(img)
    }

    pub fn create_challenge(&self, round_count: u8, request_hash: &str) -> (String, Challenge) {
        let mut rng = rng();
        let rounds: Vec<u8> = (0..round_count).map(|_| rng.random_range(5..8)).collect();
        let correct: Vec<u8> = rounds
            .iter()
            .map(|&count| rng.random_range(0..count))
            .collect();
        let icon = self.icons.choose(&mut rng).cloned().unwrap_or_default();
        let brightness = rng.random_range(0.2..0.8);

        let challenge = Challenge {
            correct,
            icon,
            brightness,
            rounds,
        };

        let token = self.encode_token(&challenge, request_hash);
        (token, challenge)
    }

    pub fn verify_answer(&self, token: &str, answers: &[u8], request_hash: &str) -> bool {
        self.decode_token(token, request_hash)
            .map(|c| c.correct == answers)
            .unwrap_or(false)
    }

    pub fn generate_clearance(&self, ip: &str, clearance_type: &str) -> String {
        let mut rng = rng();
        let nonce: [u8; 16] = rng.random();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut hasher = Sha256::new();
        hasher.update(ip.as_bytes());
        let ip_hash = hasher.finalize();
        let ip_hash_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&ip_hash[..16]);

        let nonce_b64 = general_purpose::URL_SAFE_NO_PAD.encode(nonce);
        let payload = format!(
            "{},{},{},{}",
            nonce_b64, timestamp, ip_hash_b64, clearance_type
        );

        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.hmac_key).unwrap();
        mac.update(payload.as_bytes());
        let sig = general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

        format!("{}.{}", payload, sig)
    }

    pub fn verify_clearance(&self, token: &str, ip: &str, expected_type: &str) -> bool {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 2 {
            return false;
        }

        let (payload, sig) = (parts[0], parts[1]);

        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.hmac_key).unwrap();
        mac.update(payload.as_bytes());
        let expected_sig = general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

        use subtle::ConstantTimeEq;
        let is_valid: bool = sig.as_bytes().ct_eq(expected_sig.as_bytes()).into();

        if !is_valid {
            return false;
        }

        let payload_parts: Vec<&str> = payload.split(',').collect();
        if payload_parts.len() != 4 {
            return false;
        }

        let timestamp: u64 = match payload_parts[1].parse() {
            Ok(ts) => ts,
            Err(_) => return false,
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if now >= timestamp + 3600 {
            return false;
        }

        let mut hasher = Sha256::new();
        hasher.update(ip.as_bytes());
        let ip_hash = hasher.finalize();
        let expected_ip_hash = general_purpose::URL_SAFE_NO_PAD.encode(&ip_hash[..16]);

        let token_ip_hash = payload_parts[2];
        let ip_match: bool = token_ip_hash
            .as_bytes()
            .ct_eq(expected_ip_hash.as_bytes())
            .into();

        let clearance_type = payload_parts[3];
        let type_match: bool = clearance_type
            .as_bytes()
            .ct_eq(expected_type.as_bytes())
            .into();

        ip_match && type_match
    }

    pub fn hash_request(
        url: &str,
        encrypted: bool,
        custom_code: &Option<String>,
        signature: &Option<String>,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(url.as_bytes());
        hasher.update([encrypted as u8]);
        if let Some(code) = custom_code {
            hasher.update(code.as_bytes());
        }
        if let Some(sig) = signature {
            hasher.update(sig.as_bytes());
        }
        let hash = hasher.finalize();
        general_purpose::URL_SAFE_NO_PAD.encode(&hash[..16])
    }

    fn encode_token(&self, challenge: &Challenge, request_hash: &str) -> String {
        let mut rng = rng();
        let nonce_bytes: [u8; 12] = rng.random();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let json = serde_json::to_string(challenge).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self.cipher.encrypt(nonce, json.as_bytes()).unwrap();

        let nonce_b64 = general_purpose::URL_SAFE_NO_PAD.encode(nonce_bytes);
        let encrypted = general_purpose::URL_SAFE_NO_PAD.encode(&ciphertext);
        let visible = format!("{},{},{}", nonce_b64, timestamp, request_hash);

        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.hmac_key).unwrap();
        mac.update(visible.as_bytes());
        mac.update(b".");
        mac.update(encrypted.as_bytes());
        let sig = general_purpose::URL_SAFE_NO_PAD.encode(&mac.finalize().into_bytes()[..16]);

        format!("{}.{}.{}", visible, encrypted, sig)
    }

    fn decode_token(&self, token: &str, request_hash: &str) -> Option<Challenge> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        let (visible, encrypted, sig) = (parts[0], parts[1], parts[2]);

        let visible_parts: Vec<&str> = visible.split(',').collect();
        if visible_parts.len() != 3 {
            return None;
        }
        let (nonce_b64, timestamp_str, token_hash) =
            (visible_parts[0], visible_parts[1], visible_parts[2]);

        if token_hash != request_hash {
            return None;
        }

        let timestamp: u64 = timestamp_str.parse().ok()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now > timestamp + TOKEN_TTL {
            return None;
        }

        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.hmac_key).unwrap();
        mac.update(visible.as_bytes());
        mac.update(b".");
        mac.update(encrypted.as_bytes());
        let expected_sig =
            general_purpose::URL_SAFE_NO_PAD.encode(&mac.finalize().into_bytes()[..16]);
        if sig != expected_sig {
            return None;
        }

        let nonce_bytes = general_purpose::URL_SAFE_NO_PAD.decode(nonce_b64).ok()?;
        let ciphertext = general_purpose::URL_SAFE_NO_PAD.decode(encrypted).ok()?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = self.cipher.decrypt(nonce, ciphertext.as_slice()).ok()?;
        let json = String::from_utf8(plaintext).ok()?;

        serde_json::from_str(&json).ok()
    }
}

pub fn generate_captcha_image(state: &CaptchaState, challenge: &Challenge) -> Vec<u8> {
    let total_scenes: u32 = challenge.rounds.iter().map(|&c| c as u32).sum();
    let width = (challenge.rounds.len() as u32 * REFERENCE_SIZE) + (total_scenes * IMAGE_SIZE);
    let mut combined = ImageBuffer::from_pixel(width, IMAGE_SIZE, Rgba([0, 0, 0, 0]));

    let mut x_offset = 0;
    for round_idx in 0..challenge.rounds.len() {
        draw_reference(
            state,
            &mut combined,
            x_offset,
            &challenge.icon,
            challenge.brightness,
        );
        x_offset += REFERENCE_SIZE;

        let scene_count = challenge.rounds[round_idx] as u32;
        for scene in 0..scene_count {
            draw_scene(
                state,
                &mut combined,
                x_offset,
                &challenge.icon,
                scene == challenge.correct[round_idx] as u32,
            );
            x_offset += IMAGE_SIZE;
        }
    }

    apply_distortions(&mut combined);

    let mut png = Vec::new();
    image::write_buffer_with_format(
        &mut Cursor::new(&mut png),
        combined.as_raw(),
        combined.width(),
        combined.height(),
        image::ColorType::Rgba8,
        image::ImageFormat::Png,
    )
    .unwrap();
    png
}

fn draw_reference(
    state: &CaptchaState,
    img: &mut RgbaImage,
    x_offset: u32,
    icon: &str,
    brightness: f32,
) {
    let mut rng = rng();
    if let Some(icon_img) = load_icon(state, icon, brightness) {
        let icon_x = x_offset + rng.random_range(15..(REFERENCE_SIZE - ICON_SIZE - 15));
        let icon_y = rng.random_range(15..(IMAGE_SIZE - ICON_SIZE - 15));
        overlay(img, &icon_img, icon_x as i32, icon_y as i32);
    }
}

fn draw_scene(
    state: &CaptchaState,
    img: &mut RgbaImage,
    x_offset: u32,
    target_icon: &str,
    is_correct: bool,
) {
    let mut rng = rng();

    let base = rng.random_range(0.2..0.35);
    let fills = [
        base,
        base + rng.random_range(0.1..0.2),
        base + rng.random_range(0.2..0.3),
        base + rng.random_range(0.45..0.6),
    ];

    let fullest = 3;
    let target_cup = if is_correct {
        fullest
    } else {
        rng.random_range(0..3)
    };

    let positions = generate_positions(&mut rng, x_offset);

    let mut icon_names: Vec<String> = state
        .icons
        .sample(&mut rng, 4.min(state.icons.len()))
        .cloned()
        .collect();
    if icon_names.len() < 4 {
        icon_names.resize(4, "star".to_string());
    }
    icon_names[target_cup] = target_icon.to_string();

    for (i, &(cx, cy)) in positions.iter().enumerate() {
        let cup_rotation = rng.random_range(-8.0..8.0);
        draw_cup_rotated(img, cx, cy, fills[i], cup_rotation);

        let brightness = rng.random_range(0.2..0.8);
        let icon_rotation = rng.random_range(-15.0..15.0);
        let scale = rng.random_range(0.9..1.1);

        if let Some(icon_img) = load_icon(state, &icon_names[i], brightness) {
            overlay_transformed(img, &icon_img, cx - 11, cy - 45, icon_rotation, scale);
        }
    }
}

fn generate_positions(rng: &mut impl rand::Rng, x_offset: u32) -> Vec<(i32, i32)> {
    let mut positions = Vec::with_capacity(4);
    for _ in 0..4 {
        let mut found = false;
        for _ in 0..50 {
            let x = rng.random_range(30..170) + x_offset as i32;
            let y = rng.random_range(45..180);

            if positions
                .iter()
                .all(|&(px, py): &(i32, i32)| (x - px).pow(2) + (y - py).pow(2) >= 2500)
            {
                positions.push((x, y));
                found = true;
                break;
            }
        }
        if !found {
            positions.push((
                rng.random_range(30..170) + x_offset as i32,
                rng.random_range(45..180),
            ));
        }
    }
    positions
}

fn fill_trapezoid(
    img: &mut RgbaImage,
    tl: (i32, i32),
    tr: (i32, i32),
    br: (i32, i32),
    bl: (i32, i32),
    color: Rgba<u8>,
) {
    let min_y = tl.1.min(tr.1).min(bl.1).min(br.1).max(0);
    let max_y =
        tl.1.max(tr.1)
            .max(bl.1)
            .max(br.1)
            .min(img.height() as i32 - 1);

    for y in min_y..=max_y {
        let t = if max_y != min_y {
            (y - min_y) as f32 / (max_y - min_y) as f32
        } else {
            0.0
        };
        let left = (tl.0 as f32 + (bl.0 - tl.0) as f32 * t) as i32;
        let right = (tr.0 as f32 + (br.0 - tr.0) as f32 * t) as i32;

        for x in left.max(0)..=right.min(img.width() as i32 - 1) {
            blend(img, x as u32, y as u32, color);
        }
    }
}

fn blend(img: &mut RgbaImage, x: u32, y: u32, color: Rgba<u8>) {
    if x >= img.width() || y >= img.height() {
        return;
    }
    let alpha = color[3] as u32;
    if alpha == 0 {
        return;
    }
    if alpha == 255 {
        img.put_pixel(x, y, color);
        return;
    }
    let inv = 255 - alpha;
    let pixel = img.get_pixel(x, y);
    img.put_pixel(
        x,
        y,
        Rgba([
            ((color[0] as u32 * alpha + pixel[0] as u32 * inv) / 255) as u8,
            ((color[1] as u32 * alpha + pixel[1] as u32 * inv) / 255) as u8,
            ((color[2] as u32 * alpha + pixel[2] as u32 * inv) / 255) as u8,
            (alpha + (pixel[3] as u32 * inv) / 255).min(255) as u8,
        ]),
    );
}

fn draw_line(img: &mut RgbaImage, x1: i32, y1: i32, x2: i32, y2: i32, color: Rgba<u8>) {
    let dx = (x2 - x1).abs();
    let dy = (y2 - y1).abs();
    let sx = if x1 < x2 { 1 } else { -1 };
    let sy = if y1 < y2 { 1 } else { -1 };
    let mut err = dx - dy;
    let mut x = x1;
    let mut y = y1;

    loop {
        if x >= 0 && x < img.width() as i32 && y >= 0 && y < img.height() as i32 {
            blend(img, x as u32, y as u32, color);
        }

        if x == x2 && y == y2 {
            break;
        }

        let e2 = 2 * err;
        if e2 > -dy {
            err -= dy;
            x += sx;
        }
        if e2 < dx {
            err += dx;
            y += sy;
        }
    }
}

fn overlay(base: &mut RgbaImage, overlay: &RgbaImage, x: i32, y: i32) {
    let (bw, bh) = (base.width() as i32, base.height() as i32);
    let (ow, oh) = (overlay.width() as i32, overlay.height() as i32);

    let start_x = (-x).max(0);
    let start_y = (-y).max(0);
    let end_x = (bw - x).min(ow);
    let end_y = (bh - y).min(oh);

    if start_x >= end_x || start_y >= end_y {
        return;
    }

    for oy in start_y..end_y {
        for ox in start_x..end_x {
            let overlay_x = ox as u32;
            let overlay_y = oy as u32;
            let base_x = (x + ox) as u32;
            let base_y = (y + oy) as u32;

            if overlay_x < overlay.width()
                && overlay_y < overlay.height()
                && base_x < base.width()
                && base_y < base.height()
            {
                let pixel = overlay.get_pixel(overlay_x, overlay_y);
                if pixel[3] > 0 {
                    blend(base, base_x, base_y, *pixel);
                }
            }
        }
    }
}

fn load_icon(state: &CaptchaState, name: &str, brightness: f32) -> Option<RgbaImage> {
    let bright_key = (brightness * 10.0).round() as u8;
    let key = (name.to_string(), bright_key, ICON_SIZE);

    state
        .cache
        .get(&key)
        .and_then(|data| ImageBuffer::from_raw(ICON_SIZE, ICON_SIZE, data.clone()))
}

fn draw_cup_rotated(img: &mut RgbaImage, cx: i32, cy: i32, fill: f32, rotation: f32) {
    let hw = CUP_WIDTH / 2;
    let hh = CUP_HEIGHT / 2;
    let bw = (CUP_WIDTH as f32 * 0.75) as i32 / 2;

    let angle = rotation.to_radians();
    let cos_a = angle.cos();
    let sin_a = angle.sin();

    let rotate = |x: i32, y: i32| -> (i32, i32) {
        let fx = x as f32;
        let fy = y as f32;
        (
            (fx * cos_a - fy * sin_a) as i32,
            (fx * sin_a + fy * cos_a) as i32,
        )
    };

    let (tl_x, tl_y) = rotate(-hw, -hh);
    let (tr_x, tr_y) = rotate(hw, -hh);
    let (bl_x, bl_y) = rotate(-bw, hh);
    let (br_x, br_y) = rotate(bw, hh);

    let top_left = (cx + tl_x, cy + tl_y);
    let top_right = (cx + tr_x, cy + tr_y);
    let bot_left = (cx + bl_x, cy + bl_y);
    let bot_right = (cx + br_x, cy + br_y);

    fill_trapezoid(
        img,
        top_left,
        top_right,
        bot_right,
        bot_left,
        Rgba([200, 210, 220, 180]),
    );

    if fill > 0.01 {
        let clamped_fill = fill.min(1.0);
        let liquid_height = ((CUP_HEIGHT - 4) as f32 * clamped_fill) as i32;
        let top_y = -hh + (CUP_HEIGHT - liquid_height - 2);
        let top_width = bw + ((hw - bw) * liquid_height / CUP_HEIGHT);

        let (ltl_x, ltl_y) = rotate(-top_width + 2, top_y);
        let (ltr_x, ltr_y) = rotate(top_width - 2, top_y);
        let (lbl_x, lbl_y) = rotate(-bw + 2, hh - 2);
        let (lbr_x, lbr_y) = rotate(bw - 2, hh - 2);

        fill_trapezoid(
            img,
            (cx + ltl_x, cy + ltl_y),
            (cx + ltr_x, cy + ltr_y),
            (cx + lbr_x, cy + lbr_y),
            (cx + lbl_x, cy + lbl_y),
            Rgba([70, 130, 230, 220]),
        );
    }
}

fn overlay_transformed(
    base: &mut RgbaImage,
    overlay: &RgbaImage,
    x: i32,
    y: i32,
    rotation: f32,
    scale: f32,
) {
    let angle = rotation.to_radians();
    let cos_a = angle.cos();
    let sin_a = angle.sin();

    let ow = overlay.width() as i32;
    let oh = overlay.height() as i32;
    let cx_offset = ow / 2;
    let cy_offset = oh / 2;

    let bounds = (ow as f32 * scale * 1.5) as i32;

    for dy in -bounds..bounds {
        for dx in -bounds..bounds {
            let src_x = (dx as f32 / scale * cos_a + dy as f32 / scale * sin_a) as i32;
            let src_y = (-dx as f32 / scale * sin_a + dy as f32 / scale * cos_a) as i32;

            let overlay_x = src_x + cx_offset;
            let overlay_y = src_y + cy_offset;

            if overlay_x >= 0 && overlay_x < ow && overlay_y >= 0 && overlay_y < oh {
                let base_x = x + dx + cx_offset;
                let base_y = y + dy + cy_offset;

                if base_x >= 0
                    && base_x < base.width() as i32
                    && base_y >= 0
                    && base_y < base.height() as i32
                {
                    let pixel = overlay.get_pixel(overlay_x as u32, overlay_y as u32);
                    if pixel[3] > 0 {
                        blend(base, base_x as u32, base_y as u32, *pixel);
                    }
                }
            }
        }
    }
}

fn serialize_bincode(data: &CacheData) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();

    buf.extend_from_slice(&(data.icons.len() as u64).to_le_bytes());
    for ((name, brightness, size), pixels) in &data.icons {
        buf.extend_from_slice(&(name.len() as u64).to_le_bytes());
        buf.extend_from_slice(name.as_bytes());
        buf.push(*brightness);
        buf.extend_from_slice(&size.to_le_bytes());
        buf.extend_from_slice(&(pixels.len() as u64).to_le_bytes());
        buf.extend_from_slice(pixels);
    }

    buf.extend_from_slice(&(data.names.len() as u64).to_le_bytes());
    for name in &data.names {
        buf.extend_from_slice(&(name.len() as u64).to_le_bytes());
        buf.extend_from_slice(name.as_bytes());
    }

    Ok(buf)
}

fn deserialize_bincode(data: &[u8]) -> Result<CacheData, String> {
    let mut pos = 0;

    let read_u64 = |pos: &mut usize| -> Result<u64, String> {
        if *pos + 8 > data.len() {
            return Err("Unexpected end".to_string());
        }
        let val = u64::from_le_bytes(data[*pos..*pos + 8].try_into().unwrap());
        *pos += 8;
        Ok(val)
    };

    let read_u32 = |pos: &mut usize| -> Result<u32, String> {
        if *pos + 4 > data.len() {
            return Err("Unexpected end".to_string());
        }
        let val = u32::from_le_bytes(data[*pos..*pos + 4].try_into().unwrap());
        *pos += 4;
        Ok(val)
    };

    let read_string = |pos: &mut usize| -> Result<String, String> {
        let len = read_u64(pos)? as usize;
        if *pos + len > data.len() {
            return Err("Unexpected end".to_string());
        }
        let s = String::from_utf8(data[*pos..*pos + len].to_vec())
            .map_err(|_| "Invalid UTF-8".to_string())?;
        *pos += len;
        Ok(s)
    };

    let mut icons = HashMap::new();
    let icon_count = read_u64(&mut pos)? as usize;

    for _ in 0..icon_count {
        let name = read_string(&mut pos)?;
        let brightness = data[pos];
        pos += 1;
        let size = read_u32(&mut pos)?;
        let pixel_len = read_u64(&mut pos)? as usize;
        if pos + pixel_len > data.len() {
            return Err("Unexpected end".to_string());
        }
        let pixels = data[pos..pos + pixel_len].to_vec();
        pos += pixel_len;
        icons.insert((name, brightness, size), pixels);
    }

    let name_count = read_u64(&mut pos)? as usize;
    let mut names = Vec::with_capacity(name_count);
    for _ in 0..name_count {
        names.push(read_string(&mut pos)?);
    }

    Ok(CacheData { icons, names })
}

fn apply_distortions(img: &mut RgbaImage) {
    let mut rng = rng();
    let width = img.width();
    let height = img.height();

    let original = img.clone();

    for y in 0..height {
        for x in 0..width {
            let wave_x = (y as f32 * 0.1).sin() * DISTORTION_STRENGTH;
            let wave_y = (x as f32 * 0.08).cos() * DISTORTION_STRENGTH;

            let src_x = (x as f32 + wave_x).round() as i32;
            let src_y = (y as f32 + wave_y).round() as i32;

            if src_x >= 0 && src_x < width as i32 && src_y >= 0 && src_y < height as i32 {
                let pixel = original.get_pixel(src_x as u32, src_y as u32);
                img.put_pixel(x, y, *pixel);
            }
        }
    }

    for _ in 0..(width * height) as usize {
        if rng.random::<f32>() < NOISE_DENSITY {
            let x = rng.random_range(0..width);
            let y = rng.random_range(0..height);
            let intensity = rng.random_range(40..100);
            let alpha = rng.random_range(30..80);
            blend(img, x, y, Rgba([intensity, intensity, intensity, alpha]));
        }
    }

    let line_count = rng.random_range(2..5);
    for _ in 0..line_count {
        let x1 = rng.random_range(0..width) as i32;
        let y1 = rng.random_range(0..height) as i32;
        let x2 = rng.random_range(0..width) as i32;
        let y2 = rng.random_range(0..height) as i32;
        let intensity = rng.random_range(60..120);
        draw_line(
            img,
            x1,
            y1,
            x2,
            y2,
            Rgba([intensity, intensity, intensity, 40]),
        );
    }
}
