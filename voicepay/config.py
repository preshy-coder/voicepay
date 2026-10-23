"""Settings loaded from environment variables, with optional .env file support."""
import os
from dataclasses import dataclass
from pathlib import Path


def load_env(path: str = ".env") -> None:
    """Read KEY=VALUE lines from a .env file into os.environ (existing variables win)."""
    file = Path(path)
    if not file.is_file():
        return
    for line in file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    db_path: str
    login_attempts: int
    window_seconds: int


def get_settings() -> Settings:
    return Settings(
        host=os.environ.get("VOICEPAY_HOST", "127.0.0.1"),
        port=int(os.environ.get("VOICEPAY_PORT", "8000")),
        db_path=os.environ.get("VOICEPAY_DB", "voicepay.db"),
        login_attempts=int(os.environ.get("VOICEPAY_LOGIN_ATTEMPTS", "5")),
        window_seconds=int(os.environ.get("VOICEPAY_WINDOW_SECONDS", "60")),
    )