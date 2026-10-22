"""Bank integration boundary.

All money movement goes through a BankAdapter so the rest of the app never
talks to a bank directly. Swap MockBank for a real provider adapter
(for example M-Pesa Daraja, Flutterwave or a bank's open-banking API)
without touching the service or fraud logic.
"""
import abc
import secrets
from dataclasses import dataclass
from decimal import Decimal

from . import db


@dataclass
class TransferResult:
    ok: bool
    reference: str
    message: str


class BankAdapter(abc.ABC):
    @abc.abstractmethod
    def transfer(self, idempotency_key: str, user_id: int, to_phone: str, amount: Decimal) -> TransferResult:
        """Move money. MUST be idempotent on idempotency_key."""


class MockBank(BankAdapter):
    """Sandbox bank backed by the local database. No real money moves."""

    def transfer(self, idempotency_key, user_id, to_phone, amount):
        with db.connect() as conn:
            prior = conn.execute(
                "SELECT reference FROM ledger WHERE idempotency_key=?", (idempotency_key,)
            ).fetchone()
            if prior:
                return TransferResult(True, prior["reference"], "duplicate request ignored")
            row = conn.execute("SELECT balance FROM users WHERE id=?", (user_id,)).fetchone()
            if row is None or Decimal(row["balance"]) < amount:
                return TransferResult(False, "", "insufficient funds")
            ref = "MOCK" + secrets.token_hex(5).upper()
            conn.execute("UPDATE users SET balance = balance - ? WHERE id=?", (float(amount), user_id))
            conn.execute(
                "INSERT INTO ledger(idempotency_key, user_id, to_phone, amount, reference) VALUES (?,?,?,?,?)",
                (idempotency_key, user_id, to_phone, float(amount), ref),
            )
            return TransferResult(True, ref, "transfer completed")


class DarajaAdapter(BankAdapter):  # pragma: no cover - integration stub
    """Placeholder for a real M-Pesa Daraja (B2C) integration.

    To implement: OAuth token, B2C payment request with SecurityCredential,
    and a callback endpoint that confirms the final result.
    """

    def transfer(self, idempotency_key, user_id, to_phone, amount):
        raise NotImplementedError("Add Daraja credentials and implement the B2C call")
