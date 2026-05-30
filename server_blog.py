import http.server
import socketserver
import json
import os
import time
import base64
import hmac
import hashlib
from urllib.parse import urlparse

PORT = int(os.environ.get("PORT", 8000))
DATA_FILE = "posts.json"

ADMIN_USER = "admin"
_ADMIN_PASSWORD_PLAINTEXT_DEFAULT = "Helli5_Admin@2026_Secure!"
TOKEN_SECRET = b"helli5__token_secret__2026__ultra_secure__amir_blog_panel__x91"
TOKEN_TTL_SECONDS = 24 * 60 * 60

PBKDF2_ITERATIONS = 200_000
PBKDF2_SALT = b"helli5-static-salt-change-me-2026"


def _pbkdf2_hash_password(password: str) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        PBKDF2_SALT,
        PBKDF2_ITERATIONS,
        dklen=32,
    )


ADMIN_PASSWORD_HASH = _pbkdf2_hash_password(_ADMIN_PASSWORD_PLAINTEXT_DEFAULT)


def _json_response(handler, status_code: int, obj):
    handler.send_response(status_code)
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.end_headers()
    handler.wfile.write(json.dumps(obj, ensure_ascii=False).encode("utf-8"))


def _read_json_body(handler):
    length = int(handler.headers.get("Content-Length", 0))
    raw = handler.rfile.read(length).decode("utf-8") if length > 0 else ""
    if not raw:
        return {}
    return json.loads(raw)


def _make_token(username: str) -> str:
    exp = int(time.time()) + TOKEN_TTL_SECONDS
    payload = f"{username}:{exp}".encode("utf-8")
    sig = hmac.new(TOKEN_SECRET, payload, hashlib.sha256).digest()
    token = base64.urlsafe_b64encode(payload + b"." + sig).decode("utf-8")
    return token


def _verify_token(token: str):
    try:
        data = base64.urlsafe_b64decode(token.encode("utf-8"))
        payload, sig = data.split(b".", 1)
        expected = hmac.new(TOKEN_SECRET, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return False, "bad_signature"

        username, exp_str = payload.decode("utf-8").split(":", 1)
        exp = int(exp_str)
        if time.time() > exp:
            return False, "expired"
        if username != ADMIN_USER:
            return False, "wrong_user"
        return True, "ok"
    except Exception:
        return False, "invalid_token"


def _require_admin(handler) -> bool:
    auth = handler.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        _json_response(handler, 401, {"error": "Missing Bearer token"})
        return False
    token = auth[len("Bearer "):].strip()
    ok, reason = _verify_token(token)
    if not ok:
        _json_response(handler, 401, {"error": "Invalid token", "reason": reason})
        return False
    return True


if not os.path.exists(DATA_FILE):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump([], f, ensure_ascii=False, indent=2)


class BlogHandler(http.server.SimpleHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/get_posts":
            try:
                with open(DATA_FILE, "r", encoding="utf-8") as f:
                    posts = json.load(f)
                _json_response(self, 200, posts)
            except Exception as e:
                _json_response(self, 500, {"error": str(e)})
            return

        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path == "/admin/login":
            try:
                data = _read_json_body(self)
                username = (data.get("username") or "").strip()
                password = (data.get("password") or "")

                if username != ADMIN_USER:
                    _json_response(self, 401, {"error": "Invalid credentials"})
                    return

                cand = _pbkdf2_hash_password(password)
                if not hmac.compare_digest(cand, ADMIN_PASSWORD_HASH):
                    _json_response(self, 401, {"error": "Invalid credentials"})
                    return

                token = _make_token(username)
                _json_response(self, 200, {
                    "status": "ok",
                    "token": token,
                    "ttl": TOKEN_TTL_SECONDS
                })
            except Exception as e:
                _json_response(self, 400, {"error": "Bad request", "details": str(e)})
            return

        if parsed.path == "/admin/add_post":
            if not _require_admin(self):
                return
            try:
                data = _read_json_body(self)
                title = (data.get("title") or "").strip()
                text = (data.get("text") or "").strip()

                if not title or not text:
                    _json_response(self, 400, {"error": "title and text are required"})
                    return

                with open(DATA_FILE, "r", encoding="utf-8") as f:
                    posts = json.load(f)

                posts.append({
                    "title": title,
                    "text": text,
                    "ts": int(time.time())
                })

                with open(DATA_FILE, "w", encoding="utf-8") as f:
                    json.dump(posts, f, ensure_ascii=False, indent=2)

                _json_response(self, 200, {"status": "ok"})
            except Exception as e:
                _json_response(self, 500, {"error": str(e)})
            return

        _json_response(self, 404, {"error": "Not found"})


with socketserver.TCPServer(("", PORT), BlogHandler) as httpd:
    print(f"Blog server running on port {PORT}")
    httpd.serve_forever()
