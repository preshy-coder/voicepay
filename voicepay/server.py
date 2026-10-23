"""Minimal JSON HTTP API (standard library only).

GET  /                    demo web page with microphone button
POST /register            {username, pin}
POST /login               {username, pin}                -> {token}
POST /contacts            {name, phone}                  (auth)
POST /voice/command       {text}                         (auth) -> pending transaction
POST /transactions/<id>/verify {pin, otp?}               (auth) -> executes transfer
GET  /transactions                                       (auth)
"""
import json
import re
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer

from . import bank as bank_mod, security, service
from .config import get_settings
from .notify import send_otp
from .ratelimit import RateLimiter

BANK = bank_mod.MockBank()
INDEX = Path(__file__).parent / "static" / "index.html"


_cfg = get_settings()
LIMITER = RateLimiter(_cfg.login_attempts, _cfg.window_seconds)


class Handler(BaseHTTPRequestHandler):
    notify = staticmethod(send_otp)

    def _send(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _json(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            if n > 10_000:
                raise service.ServiceError("request too large", 413)
            body = json.loads(self.rfile.read(n) or b"{}")
            if not isinstance(body, dict):
                raise ValueError
            return body
        except ValueError:
            raise service.ServiceError("invalid JSON body")

    def _user(self):
        auth = self.headers.get("Authorization", "")
        uid = security.read_token(auth[7:]) if auth.startswith("Bearer ") else None
        if uid is None:
            raise service.ServiceError("unauthorized", 401)
        return uid

    def _route(self, method):
        path = self.path.split("?")[0]
        if method == "POST" and path == "/register":
            b = self._json()
            return 201, {"user_id": service.register(str(b.get("username", "")), str(b.get("pin", "")))}
        if method == "POST" and path == "/login":
            b = self._json()
            if not LIMITER.allow(f"login:{self.client_address[0]}:{b.get('username', '')}"):
                raise service.ServiceError("too many attempts, try again later", 429)
            return 200, {"token": service.login(str(b.get("username", "")), str(b.get("pin", "")))}
        uid = self._user()
        if method == "POST" and path == "/contacts":
            b = self._json()
            return 201, {"phone": service.add_contact(uid, str(b.get("name", "")), str(b.get("phone", "")))}
        if method == "POST" and path == "/voice/command":
            return 201, service.start_transaction(uid, str(self._json().get("text", "")), self.notify)
        m = re.fullmatch(r"/transactions/([0-9a-f]{32})/verify", path)
        if method == "POST" and m:
            b = self._json()
            if not LIMITER.allow(f"verify:{uid}"):
                raise service.ServiceError("too many attempts, try again later", 429)
            otp = b.get("otp")
            return 200, service.verify_and_execute(uid, m.group(1), str(b.get("pin", "")), str(otp) if otp else None, BANK)
        if method == "GET" and path == "/transactions":
            return 200, {"transactions": service.list_transactions(uid)}
        raise service.ServiceError("not found", 404)

    def _handle(self, method):
        try:
            status, body = self._route(method)
        except service.ServiceError as e:
            status, body = e.status, {"error": str(e)}
        self._send(status, body)

    def do_GET(self):
        if self.path.split("?")[0] in ("/", "/index.html"):
            data = INDEX.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(data)
            return
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def log_message(self, *args):  # keep logs free of request details
        pass


def run(host="127.0.0.1", port=8000):
    print(f"VoicePay sandbox listening on http://{host}:{port}")
    HTTPServer((host, port), Handler).serve_forever()