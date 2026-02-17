<p align="center">
  <img src="https://github.com/tn3w/Redux/releases/download/img/ripplit.webp" alt="Ripplit">
</p>

<h1 align="center">Ripplit</h1>

<h3 align="center">Privacy-first URL shortener with client-side encryption</h3>
<p align="center">
  Self-hosted link shortening service with advanced security features, CAPTCHA protection, and phishing detection
</p>

<p align="center">
  <img src="https://img.shields.io/badge/rust-1.70+-f74c00?style=for-the-badge&logo=rust&logoColor=white" alt="Rust">
  <img src="https://img.shields.io/badge/license-Apache%202.0-blue?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/postgres-14+-336791?style=for-the-badge&logo=postgresql&logoColor=white" alt="PostgreSQL">
</p>

<p align="center">
  <a href="#-quick-start">🚀 Quick Start</a> •
  <a href="#-features">✨ Features</a> •
  <a href="#-examples">💡 Examples</a> •
  <a href="#-configuration">⚙️ Configuration</a>
</p>

## Overview

Ripplit is a self-hosted URL shortener built with Rust that prioritizes privacy and security. Unlike traditional link shorteners, Ripplit offers client-side encryption for sensitive URLs, ensuring that even the server never sees your original links. With built-in CAPTCHA protection, phishing detection, and a comprehensive reporting system, it's designed for users who need both convenience and security.

Whether you're sharing internal documentation, protecting sensitive links, or running a public shortening service, Ripplit provides the tools to do it safely.

```rust
// Example: Create a shortened link
POST /api/shorten
{
  "url": "https://example.com/very/long/url",
  "encrypted": false,
  "custom_code": "mylink"
}

// Response: "mylink"
// Access at: https://your-domain.com/mylink
```

## ✨ Features

<table>
<tr>
<td width="50%">

### Privacy & Security

- Client-side AES-256-GCM encryption
- Zero-knowledge architecture for encrypted links
- HMAC-based session management
- Constant-time cryptographic operations
- CSRF protection on all mutations

</td>
<td width="50%">

### Protection & Moderation

- Custom visual CAPTCHA system
- Phishing domain detection (auto-updated)
- Link reporting with Discord webhooks
- Rate limiting per IP and session
- Automated malicious link removal

</td>
</tr>
<tr>
<td width="50%">

### Link Management

- Custom short codes (alphanumeric + `-_`)
- Bulk operations (edit/delete)
- Click tracking with overflow protection
- Optional preview pages
- Session-based link ownership

</td>
<td width="50%">

### Performance

- Redis caching for rate limits
- Optimized release builds (`opt-level=z`)
- Async I/O with Tokio
- Pre-rendered CAPTCHA icon cache
- Minimal dependencies

</td>
</tr>
</table>

## 🚀 Quick Start

### Prerequisites

- Rust 1.70+
- PostgreSQL 14+
- Redis 6+
- Node.js (for frontend build)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/ripplit.git
cd ripplit

# Set environment variables
export RIPPLIT_SECRET_KEY=$(openssl rand -base64 32)
export DATABASE_URL="postgresql://user:password@localhost/ripplit"
export REDIS_URL="redis://localhost:6379"

# Build frontend assets
npm install
npm run build

# Build and run
cargo build --release
./target/release/ripplit
```

The service will start on `http://0.0.0.0:8080`

## 💡 Examples

### Creating Links

```bash
# Simple link shortening
curl -X POST http://localhost:8080/api/shorten \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "csrf_token": "..."}'

# Custom short code
curl -X POST http://localhost:8080/api/shorten \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "custom_code": "my-link",
    "csrf_token": "..."
  }'

# Encrypted link (client-side encryption required)
curl -X POST http://localhost:8080/api/shorten \
  -H "Content-Type: application/json" \
  -d '{
    "url": "<encrypted-payload>",
    "encrypted": true,
    "csrf_token": "..."
  }'
```

### Managing Links

```bash
# List your links
curl http://localhost:8080/api/links \
  -H "Cookie: ripplit_session=..."

# Delete a link
curl -X DELETE http://localhost:8080/api/links/mylink \
  -H "X-CSRF-Token: ..." \
  -H "Cookie: ripplit_session=..."

# Bulk delete
curl -X POST http://localhost:8080/api/links/delete \
  -H "Content-Type: application/json" \
  -d '{
    "codes": ["link1", "link2"],
    "csrf_token": "..."
  }'
```

### Reporting Links

```bash
# Submit a report
curl -X POST http://localhost:8080/api/report \
  -H "Content-Type: application/json" \
  -d '{
    "links": [{"code": "suspicious-link"}],
    "reason": "malware",
    "description": "This link contains malware",
    "captcha_token": "...",
    "captcha_answers": [2, 1, 3]
  }'
```

## ⚙️ Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `RIPPLIT_SECRET_KEY` | Yes | 32+ character secret for cryptographic operations |
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `REDIS_URL` | Yes | Redis connection string |
| `DISCORD_WEBHOOK_URL` | No | Discord webhook for report notifications |
| `BASE_URL` | No | Base URL for link generation (default: `http://localhost:8080`) |

### Rate Limits

Default limits (configurable in code):

- General requests: 30/minute per IP
- Link creation (random): 5/minute per IP
- Link creation (custom): 3/minute per IP
- CAPTCHA attempts: 5/minute per IP
- Session operations: 50/minute per session

### CAPTCHA System

Ripplit uses a custom visual CAPTCHA that requires users to identify cups containing a specific icon. The difficulty scales based on:

- Whether a custom code is requested
- Previous failure count
- Clearance cookie presence

CAPTCHA rounds: 0-5 (adaptive based on risk)

## 🔒 Security Features

### Encryption

Encrypted links use AES-256-GCM with PBKDF2 key derivation. The encryption happens client-side, and the server stores only the ciphertext. Decryption requires the token, which is never transmitted to the server.

### Session Management

- HMAC-signed session tokens
- Automatic rotation every hour
- 30-day maximum session lifetime
- Constant-time verification

### Phishing Protection

- Automatic phishing domain list updates
- Integration with public threat feeds
- Automated removal of flagged links
- Manual review workflow for reports

## 🛠️ Development

### Building from Source

```bash
# Development build
cargo build

# Run tests
cargo test

# Build frontend
npm run build

# Run with hot reload (requires cargo-watch)
cargo watch -x run
```

### Database Schema

The application automatically initializes the database schema on first run. Tables include:

- `links` - Shortened URLs and metadata
- `sessions` - User session data
- `reports` - Link abuse reports
- `report_links` - Individual links within reports

### Docker Deployment

```bash
# Using docker-compose
docker-compose up -d

# Manual build
docker build -t ripplit .
docker run -p 8080:8080 \
  -e RIPPLIT_SECRET_KEY="..." \
  -e DATABASE_URL="..." \
  -e REDIS_URL="..." \
  ripplit
```

## 📄 License

Copyright 2026 TN3W

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

---

<p align="center">
  <sub>Built with Rust, Axum, PostgreSQL, and Redis</sub>
</p>
