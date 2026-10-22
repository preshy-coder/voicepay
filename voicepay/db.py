"""SQLite storage."""
import os
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
  pin_hash TEXT NOT NULL, salt BLOB NOT NULL,
  balance REAL NOT NULL DEFAULT 50000, daily_limit REAL NOT NULL DEFAULT 50000);
CREATE TABLE IF NOT EXISTS contacts(
  user_id INTEGER NOT NULL, name TEXT NOT NULL, phone TEXT NOT NULL,
  PRIMARY KEY(user_id, name));
CREATE TABLE IF NOT EXISTS transactions(
  id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, payee_name TEXT, payee_phone TEXT NOT NULL,
  amount REAL NOT NULL, status TEXT NOT NULL, risk_score INTEGER NOT NULL, risk_reasons TEXT NOT NULL,
  requires_otp INTEGER NOT NULL DEFAULT 0, otp_hash TEXT, otp_expires REAL,
  attempts INTEGER NOT NULL DEFAULT 0, reference TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ledger(
  idempotency_key TEXT PRIMARY KEY, user_id INTEGER NOT NULL, to_phone TEXT NOT NULL,
  amount REAL NOT NULL, reference TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY, ts TEXT NOT NULL, user_id INTEGER, event TEXT NOT NULL, detail TEXT);
"""


class _Conn:
    """Context manager: commits on success, rolls back on error, always closes."""

    def __init__(self):
        self.conn = sqlite3.connect(os.environ.get("VOICEPAY_DB", "voicepay.db"))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def __enter__(self):
        return self.conn

    def __exit__(self, exc_type, *_):
        (self.conn.rollback if exc_type else self.conn.commit)()
        self.conn.close()


def connect() -> _Conn:
    return _Conn()
