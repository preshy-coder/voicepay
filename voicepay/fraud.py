"""Rule-based fraud scoring. Each rule adds risk points and a human-readable reason.

Decision policy:
    score <  30  -> ALLOW      (PIN only)
    30 <= score < 70 -> STEP_UP (PIN + one-time code)
    score >= 70  -> BLOCK
"""
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import List, Sequence

STEP_UP_AT = 30
BLOCK_AT = 70


@dataclass
class TxnRecord:
    amount: Decimal
    created_at: datetime
    status: str


@dataclass
class RiskResult:
    score: int = 0
    reasons: List[str] = field(default_factory=list)

    @property
    def decision(self) -> str:
        if self.score >= BLOCK_AT:
            return "BLOCK"
        if self.score >= STEP_UP_AT:
            return "STEP_UP"
        return "ALLOW"

    def add(self, points: int, reason: str) -> None:
        self.score += points
        self.reasons.append(reason)


def assess(
    amount: Decimal,
    known_payee: bool,
    history: Sequence[TxnRecord],
    daily_limit: Decimal,
    now: datetime,
) -> RiskResult:
    risk = RiskResult()
    completed = [t for t in history if t.status == "COMPLETED"]

    spent_today = sum((t.amount for t in completed if t.created_at.date() == now.date()), Decimal(0))
    if spent_today + amount > daily_limit:
        risk.add(100, f"exceeds daily limit of {daily_limit}")

    if not known_payee:
        risk.add(30, "new payee")

    if len(completed) >= 3:
        avg = sum((t.amount for t in completed), Decimal(0)) / len(completed)
        if amount >= avg * 5:
            risk.add(30, "amount is 5x or more your usual transfer")

    recent = [t for t in history if (now - t.created_at).total_seconds() <= 600]
    if len(recent) >= 3:
        risk.add(30, "many transactions in the last 10 minutes")

    if any(t.status == "FAILED_VERIFICATION" for t in recent):
        risk.add(25, "recent failed verification")

    if 0 <= now.hour < 5:
        risk.add(15, "unusual hour")

    if amount >= 20000:
        risk.add(20, "high-value transfer")

    return risk
