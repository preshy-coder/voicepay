"""PIN hashing, OTP handling and signed session tokens (standard library only)."""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Optional

_PBKDF2_ROUNDS = 200_000
SECRET = os.environ.get("VOICEPAY_SECRET", secrets.token_hex(32)).encode()


def hash_secret(value: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", value.encode(), salt, _PBKDF2_ROUNDS).hex()


def new_salt() -> bytes:
    return secrets.token_bytes(16)


def check_secret(value: str, salt: bytes, expected_hex: str) -> bool:
    return hmac.compare_digest(hash_secret(value, salt), expected_hex)


def new_otp() -> str:
    return f"{secrets.randbelow(10**6):06d}"


def hash_otp(otp: str, txn_id: str) -> str:
    return hmac.new(SECRET, f"{txn_id}:{otp}".encode(), hashlib.sha256).hexdigest()


def check_otp(otp: str, txn_id: str, expected_hex: str) -> bool:
    return hmac.compare_digest(hash_otp(otp, txn_id), expected_hex)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def make_token(user_id: int, ttl: int = 900, now: Optional[float] = None) -> str:
    payload = _b64(json.dumps({"uid": user_id, "exp": (now or time.time()) + ttl}).encode())
    sig = _b64(hmac.new(SECRET, payload.encode(), hashlib.sha256).digest())
    return f"{payload}.{sig}"


def read_token(token: str, now: Optional[float] = None) -> Optional[int]:
    try:
        payload, sig = token.split(".")
        good = _b64(hmac.new(SECRET, payload.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, good):
            return None
        data = json.loads(_unb64(payload))
        if data["exp"] < (now or time.time()):
            return None
        return int(data["uid"])
    except (ValueError, KeyError, TypeError):
        return None
