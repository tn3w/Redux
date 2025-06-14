#! /usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Redux URL Shortener

A secure link shortener PWA that allows users to create and manage links,
with optional end-to-end encryption for enhanced privacy.
"""

import os
import time
import json
import string
import secrets
import base64
import hashlib
import hmac
import urllib.request
import urllib.parse
import urllib.error
from typing import Optional, Tuple, Dict, Any, Callable
from urllib.parse import urlparse
from functools import wraps
from pathlib import Path

import redis
from flask import Flask, Response, request, render_template, jsonify, abort, redirect
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


def load_dotenv(env_file=".env"):
    """Load environment variables from a .env file into os.environ."""

    if os.path.exists(env_file):
        with open(env_file, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = [part.strip() for part in line.split("=", 1)]
                    if (value.startswith('"') and value.endswith('"')) or (
                        value.startswith("'") and value.endswith("'")
                    ):
                        value = value[1:-1]
                    os.environ[key] = value


load_dotenv(os.environ.get("ENV_FILE", ".env"))

redis_client = redis.Redis(
    host=os.environ.get("REDIS_HOST", "localhost"),
    port=int(os.environ.get("REDIS_PORT", 6379)),
    db=int(os.environ.get("REDIS_DB", 0)),
    password=os.environ.get("REDIS_PASSWORD", None),
    decode_responses=True,
)

HCAPTCHA_SITE_KEY = os.environ.get(
    "HCAPTCHA_SITE_KEY", "10000000-ffff-ffff-ffff-000000000001"
)
HCAPTCHA_SECRET_KEY = os.environ.get(
    "HCAPTCHA_SECRET_KEY", "0x0000000000000000000000000000000000000000"
)
CLEARANCE_EXPIRY = 60 * 60 * 24
SESSION_COOKIE_NAME = "redux_session"
SESSION_MAX_AGE = 60 * 60 * 24 * 365
LONG_HOST_NAME = os.environ.get("LONG_HOST_NAME", None)
SHORT_HOST_NAME = os.environ.get("SHORT_HOST_NAME", None)

URL_LENGTH = 5
MAX_URL_LENGTH = 320
URL_EXPIRY = 60 * 60 * 24 * 365
MAX_URLS_PER_SESSION = 50

BUILD_DIR = os.environ.get("BUILD_DIR") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "build"
)
USE_BUILD_DIR = os.path.exists(BUILD_DIR)

STATIC_DIR = Path(BUILD_DIR) if USE_BUILD_DIR else Path("static")
ROBOTS_TXT = (
    (STATIC_DIR / "robots.txt").read_text()
    if (STATIC_DIR / "robots.txt").exists()
    else ""
)
SECURITY_TXT = (
    (STATIC_DIR / "security.txt").read_text()
    if (STATIC_DIR / "security.txt").exists()
    else ""
)
FAVICON = (
    (STATIC_DIR / "favicon.ico").read_bytes()
    if (STATIC_DIR / "favicon.ico").exists()
    else None
)

app = Flask(
    __name__,
    static_folder="static" if not USE_BUILD_DIR else None,
    template_folder="templates" if not USE_BUILD_DIR else BUILD_DIR,
)

secret_key = redis_client.get("app:secret_key")
if not secret_key:
    secret_key = secrets.token_hex(36)
    redis_client.set("app:secret_key", secret_key)
app.secret_key = secret_key


def sign_data(data: Dict[str, Any]) -> str:
    """Sign session data with HMAC"""
    data_json = json.dumps(data, sort_keys=True)
    data_b64 = base64.urlsafe_b64encode(data_json.encode()).decode()
    signature = hmac.new(
        app.secret_key.encode(), data_b64.encode(), hashlib.sha256
    ).hexdigest()
    return f"{data_b64}.{signature}"


def validate_signature(signed_data: str) -> Optional[Dict[str, Any]]:
    """Validate and return session data"""
    try:
        data_b64, signature = signed_data.split(".", 1)
        expected_signature = hmac.new(
            app.secret_key.encode(), data_b64.encode(), hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_signature):
            return None

        data_json = base64.urlsafe_b64decode(data_b64).decode()
        return json.loads(data_json)
    except (ValueError, json.JSONDecodeError):
        return None


def get_session() -> Dict[str, Any]:
    """Get session data from cookie"""
    if request.path.startswith("/api/"):
        session_cookie = request.headers.get("X-Session")

    if not session_cookie:
        session_cookie = request.cookies.get(SESSION_COOKIE_NAME)

    if not session_cookie:
        return {}

    session_data = validate_signature(session_cookie)
    return session_data or {}


def set_session(response: Response, data: Dict[str, Any]) -> Response:
    """Set session data in cookie"""
    signed_data = sign_data(data)

    cookie_domain = None
    if SHORT_HOST_NAME:
        dot_pos = SHORT_HOST_NAME.find(".")
        if dot_pos != -1:
            cookie_domain = "." + SHORT_HOST_NAME[dot_pos + 1 :]

    response.set_cookie(
        SESSION_COOKIE_NAME,
        signed_data,
        max_age=SESSION_MAX_AGE,
        httponly=False,
        samesite="Lax",
        secure=request.is_secure,
        domain=cookie_domain,
    )
    return response


def generate_random_string(length: int) -> str:
    """Generate a random URL ID"""
    alphabet = string.ascii_letters + string.digits + "-_"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def is_valid_url(url: str, disallowed_hostnames: list = None) -> bool:
    """Check if URL is valid"""
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            return False

        if disallowed_hostnames and result.netloc in disallowed_hostnames:
            return False

        return True
    except (TypeError, AttributeError, ValueError):
        return False


def create_url_shortener(
    url: str, is_encrypted: bool, signature: Optional[str] = None
) -> str:
    """Create a URL shortener"""
    while True:
        url_id = generate_random_string(URL_LENGTH)
        if not redis_client.exists(f"url:{url_id}"):
            break

    url_data = {
        "url": url,
        "is_encrypted": is_encrypted,
        "created_at": int(time.time()),
        "visits": 0,
    }

    if signature:
        url_data["signature"] = signature

    redis_client.set(f"url:{url_id}", json.dumps(url_data), ex=URL_EXPIRY)
    return url_id


def get_session_id() -> str:
    """Get the session ID. Returns None if no valid clearance exists."""
    session_data = get_session()
    if "session_id" not in session_data:
        return None

    return session_data["session_id"]


@app.route("/", methods=["GET", "POST"])
def index() -> Response:
    """Main page"""
    response = Response(
        render_template(
            "index.html",
            hcaptcha_site_key=HCAPTCHA_SITE_KEY,
            short_host_name=SHORT_HOST_NAME,
        )
    )
    response.headers["Cache-Control"] = "public, max-age=31536000"
    return response


@app.route("/robots.txt", methods=["GET"])
def robots_txt():
    """
    Return the robots.txt file.
    """
    if not ROBOTS_TXT:
        return abort(404)

    response = Response(ROBOTS_TXT, mimetype="text/plain")
    response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    return response


@app.route("/.well-known/security.txt", methods=["GET"])
def security_txt():
    """
    Return the security.txt file.
    """
    if not SECURITY_TXT:
        return abort(404)

    response = Response(SECURITY_TXT, mimetype="text/plain")
    response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    return response


@app.route("/favicon.ico", methods=["GET"])
def favicon():
    """
    Return the favicon.ico file.
    """
    if not FAVICON:
        return abort(404)

    response = Response(FAVICON, mimetype="image/x-icon")
    response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    return response


@app.errorhandler(404)
def page_not_found(_: Exception) -> Tuple[Response, int]:
    """404 page"""
    return render_template("404.html"), 404


def get_client_ip() -> str:
    """Get the client's IP address."""
    client_ip = request.remote_addr
    if client_ip == "127.0.0.1":
        client_ip = request.headers.get("X-Forwarded-For", "")
    return client_ip


def get_user_info() -> dict:
    """Get information about the user."""
    client_ip = get_client_ip()
    user_agent = request.headers.get("User-Agent", "")

    return {
        "ip": client_ip,
        "user_agent": user_agent,
    }


def get_user_hash(user_info: dict) -> str:
    """Get a hash of the user's IP and user agent."""
    return hashlib.sha256(":".join(user_info.values()).encode()).hexdigest()


def generate_clearance_token(user_hash: str) -> str:
    """Generate a signed clearance token using HMAC."""
    timestamp = str(int(time.time()))
    message = f"{user_hash}:{timestamp}"
    signature = hmac.new(
        app.secret_key.encode(), message.encode(), hashlib.sha256
    ).hexdigest()

    clearance_token = f"{message}:{signature}"
    return base64.urlsafe_b64encode(clearance_token.encode()).decode()


def verify_clearance_token(token: str, user_info: dict) -> bool:
    """Verify a clearance token."""
    try:
        decoded_token = base64.urlsafe_b64decode(token).decode()
        user_hash, timestamp, signature = decoded_token.rsplit(":", 2)

        current_time = int(time.time())
        token_time = int(timestamp)
        if current_time - token_time > CLEARANCE_EXPIRY:
            return False

        if user_hash != get_user_hash(user_info):
            return False

        message = f"{user_hash}:{timestamp}"
        expected_signature = hmac.new(
            app.secret_key.encode(), message.encode(), hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(signature, expected_signature)
    except (ValueError, UnicodeDecodeError, base64.binascii.Error):
        return False


def rate_limit(limit: int, window: int = 60):
    """
    Rate limiting decorator that uses Redis

    Args:
        limit: Maximum number of requests allowed in the window
        window: Time window in seconds (default: 60 seconds)
    """

    def decorator(f: Callable):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = get_client_ip()
            ip_hash = hashlib.sha256(client_ip.encode()).hexdigest()

            endpoint = request.path.replace("/api/", "")
            rate_limit_key = f"ratelimit:{endpoint}:{ip_hash}"

            current_count = redis_client.get(rate_limit_key)
            current_count = int(current_count) if current_count else 0

            if current_count >= limit:
                response = jsonify(
                    {"error": "Rate limit exceeded", "retry_after": window}
                )
                response.status_code = 429
                response.headers["Retry-After"] = str(window)
                return response

            pipeline = redis_client.pipeline()
            pipeline.incr(rate_limit_key)
            pipeline.expire(rate_limit_key, window)
            pipeline.execute()

            return f(*args, **kwargs)

        return decorated_function

    return decorator


@app.route("/api/clearance", methods=["POST"])
@rate_limit(1)
def get_clearance() -> Tuple[Response, int]:
    """Verify hCaptcha and generate clearance token."""
    session_data = get_session()

    if "clearance_token" in session_data and verify_clearance_token(
        session_data["clearance_token"], get_user_info()
    ):
        if not session_data.get("session_id"):
            session_data["session_id"] = generate_random_string(32)

        response = jsonify({"success": True})
        return set_session(response, session_data), 200

    data = request.json
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    hcaptcha_response = data.get("h-captcha-response")
    if not hcaptcha_response:
        return jsonify({"error": "hCaptcha response required"}), 400

    verification_data = {
        "secret": HCAPTCHA_SECRET_KEY,
        "response": hcaptcha_response,
        "sitekey": HCAPTCHA_SITE_KEY,
    }

    data = urllib.parse.urlencode(verification_data).encode()

    try:
        req = urllib.request.Request(
            "https://hcaptcha.com/siteverify", data=data, method="POST"
        )

        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())

        if not result.get("success", False):
            return jsonify({"error": "hCaptcha verification failed"}), 400

        user_hash = get_user_hash(get_user_info())
        clearance_token = generate_clearance_token(user_hash)

        session_data["clearance_token"] = clearance_token
        if not session_data.get("session_id"):
            session_data["session_id"] = generate_random_string(32)

        response = jsonify({"success": True})
        return set_session(response, session_data), 200

    except (urllib.error.URLError, json.JSONDecodeError):
        return jsonify({"error": "hCaptcha verification error."}), 500


@app.route("/api/shorten", methods=["POST"])
@rate_limit(20)
def api_shorten() -> Tuple[Response, int]:
    """Shorten a URL"""
    data = request.json
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    session_data = get_session()
    if "clearance_token" not in session_data or not verify_clearance_token(
        session_data["clearance_token"], get_user_info()
    ):
        return jsonify({"error": "Valid clearance required"}), 403

    session_id = get_session_id()
    new_session_data = None
    if not session_id:
        session_id = generate_random_string(32)
        new_session_data = session_data
        new_session_data["session_id"] = session_id

    if redis_client.scard(f"session:{session_id}:urls") >= MAX_URLS_PER_SESSION:
        return jsonify({"error": "Maximum number of URLs reached"}), 403

    is_encrypted = data.get("is_encrypted", False)
    url = data.get("url")

    if not url:
        return jsonify({"error": "URL is required"}), 400

    signature = None
    if not is_encrypted:
        disallowed_hostnames = [
            hostname
            for hostname in [
                request.host,
                LONG_HOST_NAME,
                SHORT_HOST_NAME,
            ]
            if hostname
        ]
        if not is_valid_url(url, disallowed_hostnames):
            return jsonify({"error": "Invalid URL"}), 400

        if len(url) > MAX_URL_LENGTH:
            return jsonify({"error": "URL is too long"}), 400
    else:
        if url.startswith(("http://", "https://")):
            return jsonify({"error": "URL must be encrypted"}), 400

        signature = data.get("signature")
        if not signature or len(signature) != 43:
            return jsonify({"error": "Signature is required"}), 400

    url_id = create_url_shortener(url, is_encrypted, signature)
    redis_client.sadd(f"session:{session_id}:urls", url_id)

    response = jsonify({"url_id": url_id})

    if new_session_data:
        response = set_session(response, new_session_data)

    return response, 201


@app.route("/api/url/<url_id>", methods=["GET"])
@app.route("/api/redirect/<url_id>", methods=["GET"])
def api_redirect(url_id: str) -> Tuple[Response, int]:
    """Redirect a URL"""
    if len(url_id) != URL_LENGTH:
        return jsonify({"error": "URL not found"}), 404

    raw_url_data = redis_client.get(f"url:{url_id}")
    if not raw_url_data:
        return jsonify({"error": "URL not found"}), 404

    url_data = json.loads(raw_url_data)

    if request.path.startswith("/api/redirect/"):
        url_data["visits"] += 1
        redis_client.set(f"url:{url_id}", json.dumps(url_data), ex=URL_EXPIRY)

    response_data = {
        "url": url_data["url"],
        "is_encrypted": url_data["is_encrypted"],
        "signature": url_data.get("signature", None),
    }

    if not request.path.startswith("/api/redirect/"):
        session_id = get_session_id()
        if redis_client.sismember(f"session:{session_id}:urls", url_id):
            response_data["visits"] = url_data["visits"]
            response_data["created_at"] = url_data["created_at"]

    return jsonify(response_data), 200


@app.route("/api/urls", methods=["GET"])
def get_user_urls() -> Tuple[Response, int]:
    """Get all URLs by the user"""
    session_id = get_session_id()
    if not session_id:
        return jsonify({"error": "Valid clearance required"}), 403

    url_ids = redis_client.smembers(f"session:{session_id}:urls")

    urls = []
    for url_id in url_ids:
        raw_url_data = redis_client.get(f"url:{url_id}")
        if raw_url_data:
            url_data = json.loads(raw_url_data)
            urls.append(
                {
                    "url_id": url_id,
                    "url": url_data["url"],
                    "created_at": url_data["created_at"],
                    "visits": url_data["visits"],
                    "is_encrypted": url_data["is_encrypted"],
                }
            )

    return jsonify(urls), 200


@app.route("/api/url/<url_id>", methods=["DELETE"])
def delete_url(url_id: str) -> Tuple[Response, int]:
    """Delete a URL"""
    if len(url_id) != URL_LENGTH:
        return jsonify({"error": "URL not found"}), 404

    session_id = get_session_id()
    if not session_id:
        return jsonify({"error": "Valid clearance required"}), 403

    if not redis_client.sismember(f"session:{session_id}:urls", url_id):
        return jsonify({"error": "URL not found or unauthorized"}), 403

    redis_client.delete(f"url:{url_id}")
    redis_client.srem(f"session:{session_id}:urls", url_id)

    return jsonify({"success": True}), 200


@app.route("/api/url/<url_id>", methods=["PUT"])
def update_url(url_id: str) -> Tuple[Response, int]:
    """Update a URL"""
    if len(url_id) != URL_LENGTH:
        return jsonify({"error": "URL not found"}), 404

    session_id = get_session_id()
    if not session_id:
        return jsonify({"error": "Valid clearance required"}), 403

    if not redis_client.sismember(f"session:{session_id}:urls", url_id):
        return jsonify({"error": "URL not found or unauthorized"}), 403

    raw_url_data = redis_client.get(f"url:{url_id}")
    if not raw_url_data:
        return jsonify({"error": "URL not found"}), 404

    url_data = json.loads(raw_url_data)

    if url_data["is_encrypted"]:
        return jsonify({"error": "Encrypted URLs cannot be modified"}), 400

    data = request.json
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    url = data.get("url")

    if not url:
        return jsonify({"error": "URL is required"}), 400

    if not is_valid_url(url):
        return jsonify({"error": "Invalid URL"}), 400

    if len(url) > MAX_URL_LENGTH:
        return jsonify({"error": "URL is too long"}), 400

    url_data["url"] = url
    redis_client.set(f"url:{url_id}", json.dumps(url_data), ex=URL_EXPIRY)

    return jsonify({"success": True}), 200


def decrypt_url(encrypted_url: str, token: str, signature: str) -> Optional[str]:
    """Decrypt a URL using the provided token."""
    try:
        token_bytes = token.encode()
        if len(token_bytes) < 16:
            token_bytes = token_bytes.ljust(16, b"_")

        h = hmac.new(token_bytes, encrypted_url.encode(), hashlib.sha256)
        calculated_signature = (
            base64.urlsafe_b64encode(h.digest()).decode().replace("=", "")
        )

        if not hmac.compare_digest(calculated_signature, signature):
            return None

        encrypted_url = encrypted_url.replace("-", "+").replace("_", "/")
        padding = 4 - (len(encrypted_url) % 4)
        if padding < 4:
            encrypted_url += "=" * padding

        encrypted_bytes = base64.b64decode(encrypted_url)

        iv = encrypted_bytes[:12]
        ciphertext = encrypted_bytes[12:]

        token_bytes = token.encode()
        if len(token_bytes) < 16:
            token_bytes = token_bytes.ljust(16, b"_")

        salt = b"Redux URL Salt"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(token_bytes)

        aesgcm = AESGCM(key)
        decrypted_bytes = aesgcm.decrypt(iv, ciphertext, None)

        return decrypted_bytes.decode("utf-8")
    except (ValueError, UnicodeDecodeError, base64.binascii.Error, InvalidTag):
        return None


@app.route("/<url_id>")
def redirect_to_url(url_id: str):
    """Redirect to a URL"""
    if len(url_id) not in (URL_LENGTH, URL_LENGTH + 14):
        return abort(404)

    token = None
    if len(url_id) > URL_LENGTH:
        token = url_id[URL_LENGTH:]
        url_id = url_id[:URL_LENGTH]

    raw_url_data = redis_client.get(f"url:{url_id}")
    if not raw_url_data:
        return abort(404)

    url_data = json.loads(raw_url_data)
    url_data["visits"] += 1
    redis_client.set(f"url:{url_id}", json.dumps(url_data), ex=URL_EXPIRY)

    if url_data["is_encrypted"]:
        if not token:
            return abort(404)

        decrypted_url = decrypt_url(url_data["url"], token, url_data["signature"])
        if decrypted_url:
            return redirect(decrypted_url)

        return abort(404)

    return redirect(url_data["url"])


if __name__ == "__main__":
    HOST = os.environ.get("HOST", "0.0.0.0")
    PORT = int(os.environ.get("PORT", 5000))
    app.run(host=HOST, port=PORT, debug=False)
