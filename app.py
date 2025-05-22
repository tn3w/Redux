import os
import time
import json
import string
import secrets
import base64
from typing import Optional, Tuple
from urllib.parse import urlparse

import redis
from flask import Flask, Response, request, render_template, jsonify, abort, redirect, session
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

redis_client = redis.Redis(
    host=os.environ.get("REDIS_HOST", "localhost"),
    port=int(os.environ.get("REDIS_PORT", 6379)),
    db=int(os.environ.get("REDIS_DB", 0)),
    password=os.environ.get("REDIS_PASSWORD", None),
    decode_responses=True,
)

app = Flask(__name__, static_folder="static", template_folder="templates")
secret_key = redis_client.get("app:secret_key")
if not secret_key:
    secret_key = secrets.token_hex(36)
    redis_client.set("app:secret_key", secret_key)
app.secret_key = secret_key

URL_LENGTH = 5
MAX_URL_LENGTH = 320
URL_EXPIRY = 60 * 60 * 24 * 365


def generate_random_string(length: int) -> str:
    """Generate a random URL ID"""
    alphabet = string.ascii_letters + string.digits + "-_"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def is_valid_url(url: str) -> bool:
    """Check if URL is valid"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def create_url_shortener(url: str, is_encrypted: bool) -> str:
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

    redis_client.set(f"url:{url_id}", json.dumps(url_data), ex=URL_EXPIRY)
    return url_id


def get_session_id() -> str:
    """Get the session ID"""
    if "session_id" not in session:
        session["session_id"] = generate_random_string(32)
    return session["session_id"]


@app.route("/", methods=["GET", "POST"])
def index() -> str:
    """Main page"""
    return render_template("index.html")


@app.route("/api/shorten", methods=["POST"])
def api_shorten() -> Tuple[Response, int]:
    """Shorten a URL"""
    data = request.json
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    is_encrypted = data.get("is_encrypted", False)
    url = data.get("url")

    if not url:
        return jsonify({"error": "URL is required"}), 400

    if not is_encrypted:
        if not is_valid_url(url):
            return jsonify({"error": "Invalid URL"}), 400

        if len(url) > MAX_URL_LENGTH:
            return jsonify({"error": "URL is too long"}), 400
    else:
        if url.startswith(("http://", "https://")):
            return jsonify({"error": "URL must be encrypted"}), 400

    url_id = create_url_shortener(url, is_encrypted)
    session_id = get_session_id()
    redis_client.sadd(f"session:{session_id}:urls", url_id)
    return jsonify({"url_id": url_id}), 201


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
    }

    session_id = get_session_id()
    if redis_client.sismember(f"session:{session_id}:urls", url_id):
        response_data["visits"] = url_data["visits"]
        response_data["created_at"] = url_data["created_at"]

    return jsonify(response_data), 200


@app.route("/api/urls", methods=["GET"])
def get_user_urls() -> Tuple[Response, int]:
    """Get all URLs by the user"""
    session_id = get_session_id()
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


def decrypt_url(encrypted_url: str, token: str) -> Optional[str]:
    """Decrypt a URL using the provided token."""
    try:
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
    except Exception:
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

        decrypted_url = decrypt_url(url_data["url"], token)
        if decrypted_url:
            return redirect(decrypted_url)

        return abort(404)

    return redirect(url_data["url"])


if __name__ == "__main__":
    app.run(debug=True)
