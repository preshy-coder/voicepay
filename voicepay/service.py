"""Business logic: register, authenticate, interpret a voice command, verify, execute."""
import json
import time
import uuid
from datetime import datetime
from decimal import Decimal
from typing import Callable, Optional

from . import bank as bank_mod, db, fraud, parser, security

MAX_ATTEMPTS = 3
OTP_TTL = 300


class ServiceError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _audit(conn, user_id, event, detail=""):
    conn.execute(
        "INSERT INTO audit(ts, user_id, event, detail) VALUES (?,?,?,?)",
        (datetime.now().isoformat(timespec="seconds"), user_id, event, detail),
    )


def register(username: str, pin: str) -> int:
    if not (4 <= len(pin) <= 6 and pin.isdigit()):
        raise ServiceError("PIN must be 4 to 6 digits")
    if not username or len(username) > 40:
        raise ServiceError("invalid username")
    salt = security.new_salt()
    with db.connect() as conn:
        if conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            raise ServiceError("username taken", 409)
        cur = conn.execute(
            "INSERT INTO users(username, pin_hash, salt) VALUES (?,?,?)",
            (username, security.hash_secret(pin, salt), salt),
        )
        _audit(conn, cur.lastrowid, "REGISTER")
        return cur.lastrowid


def login(username: str, pin: str) -> str:
    with db.connect() as conn:
        u = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not u or not security.check_secret(pin, u["salt"], u["pin_hash"]):
            _audit(conn, u["id"] if u else None, "LOGIN_FAILED", username)
            raise ServiceError("invalid credentials", 401)
        _audit(conn, u["id"], "LOGIN")
        return security.make_token(u["id"])


def add_contact(user_id: int, name: str, phone: str) -> str:
    norm = parser.normalize_phone(phone)
    if not norm:
        raise ServiceError("invalid phone number")
    with db.connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO contacts(user_id, name, phone) VALUES (?,?,?)",
            (user_id, name.strip().lower(), norm),
        )
    return norm


def _history(conn, user_id, payee_phone=None):
    rows = conn.execute("SELECT amount, created_at, status FROM transactions WHERE user_id=?", (user_id,)).fetchall()
    return [fraud.TxnRecord(Decimal(str(r["amount"])), datetime.fromisoformat(r["created_at"]), r["status"]) for r in rows]


def start_transaction(
    user_id: int,
    text: str,
    notify_otp: Callable[[int, str], None],
    now: Optional[datetime] = None,
) -> dict:
    """Parse a voice command and create a pending transaction. Does NOT move money."""
    now = now or datetime.now()
    intent = parser.parse_command(text)
    if not intent:
        raise ServiceError("sorry, I did not understand that command")

    with db.connect() as conn:
        phone = parser.normalize_phone(intent.target)
        payee_name = None
        if phone is None:
            c = conn.execute(
                "SELECT phone FROM contacts WHERE user_id=? AND name=?", (user_id, intent.target)
            ).fetchone()
            if not c:
                raise ServiceError(f"I could not find a contact named '{intent.target}'")
            phone, payee_name = c["phone"], intent.target
        else:
            c = conn.execute("SELECT name FROM contacts WHERE user_id=? AND phone=?", (user_id, phone)).fetchone()
            payee_name = c["name"] if c else None

        paid_before = conn.execute(
            "SELECT 1 FROM transactions WHERE user_id=? AND payee_phone=? AND status='COMPLETED'",
            (user_id, phone),
        ).fetchone()
        known = bool(payee_name) or bool(paid_before)
        user = conn.execute("SELECT daily_limit FROM users WHERE id=?", (user_id,)).fetchone()
        risk = fraud.assess(intent.amount, known, _history(conn, user_id), Decimal(str(user["daily_limit"])), now)

        txn_id = uuid.uuid4().hex
        status = "BLOCKED" if risk.decision == "BLOCK" else "AWAITING_VERIFICATION"
        needs_otp = risk.decision == "STEP_UP"
        otp_hash = otp_expires = None
        otp = None
        if needs_otp:
            otp = security.new_otp()
            otp_hash, otp_expires = security.hash_otp(otp, txn_id), time.time() + OTP_TTL
        conn.execute(
            "INSERT INTO transactions(id,user_id,payee_name,payee_phone,amount,status,risk_score,risk_reasons,"
            "requires_otp,otp_hash,otp_expires,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (txn_id, user_id, payee_name, phone, float(intent.amount), status, risk.score,
             json.dumps(risk.reasons), int(needs_otp), otp_hash, otp_expires, now.isoformat()),
        )
        _audit(conn, user_id, f"TXN_{status}", f"{txn_id} score={risk.score} {risk.reasons}")

    if otp:
        notify_otp(user_id, otp)  # delivered out-of-band (SMS in production)
    who = f"{payee_name} ({phone})" if payee_name else phone
    return {
        "transaction_id": txn_id,
        "status": status,
        "confirmation": None if status == "BLOCKED" else f"Send KES {intent.amount:,.2f} to {who}? Confirm with your PIN"
        + (" and the code we sent you." if needs_otp else "."),
        "requires_otp": needs_otp,
        "risk_score": risk.score,
        "risk_reasons": risk.reasons,
    }


def verify_and_execute(user_id: int, txn_id: str, pin: str, otp: Optional[str], bank: bank_mod.BankAdapter) -> dict:
    with db.connect() as conn:
        t = conn.execute("SELECT * FROM transactions WHERE id=? AND user_id=?", (txn_id, user_id)).fetchone()
        if not t:
            raise ServiceError("transaction not found", 404)
        if t["status"] == "COMPLETED":
            return {"status": "COMPLETED", "reference": t["reference"]}  # idempotent replay
        if t["status"] != "AWAITING_VERIFICATION":
            raise ServiceError(f"transaction is {t['status'].lower()}", 409)

        user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        ok = security.check_secret(pin, user["salt"], user["pin_hash"])
        if ok and t["requires_otp"]:
            ok = bool(otp) and time.time() <= (t["otp_expires"] or 0) and security.check_otp(otp, txn_id, t["otp_hash"])
        if not ok:
            attempts = t["attempts"] + 1
            new_status = "FAILED_VERIFICATION" if attempts >= MAX_ATTEMPTS else "AWAITING_VERIFICATION"
            conn.execute("UPDATE transactions SET attempts=?, status=? WHERE id=?", (attempts, new_status, txn_id))
            _audit(conn, user_id, "VERIFY_FAILED", f"{txn_id} attempt {attempts}")
            conn.commit()
            raise ServiceError("verification failed" + (" - transaction cancelled" if attempts >= MAX_ATTEMPTS else ""), 401)

    result = bank.transfer(txn_id, user_id, t["payee_phone"], Decimal(str(t["amount"])))
    with db.connect() as conn:
        conn.execute(
            "UPDATE transactions SET status=?, reference=? WHERE id=?",
            ("COMPLETED" if result.ok else "FAILED", result.reference or None, txn_id),
        )
        _audit(conn, user_id, "TXN_COMPLETED" if result.ok else "TXN_FAILED", f"{txn_id} {result.message}")
    if not result.ok:
        raise ServiceError(result.message, 422)
    return {"status": "COMPLETED", "reference": result.reference, "message": result.message}


def list_transactions(user_id: int) -> list:
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT id, payee_name, payee_phone, amount, status, risk_score, created_at "
            "FROM transactions WHERE user_id=? ORDER BY created_at DESC", (user_id,)).fetchall()
        return [dict(r) for r in rows]
