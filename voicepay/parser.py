"""Turns a spoken (already transcribed) command into a structured payment intent."""
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Optional

_VERBS = r"(?:send|transfer|pay|give)"
_CUR = r"(?:ksh|kes|kshs|shillings?|bob|\$)?"
_AMOUNT = r"(?P<amount>\d[\d,]*(?:\.\d+)?)\s*(?P<k>k)?"
_PATTERNS = [
    # "send 500 shillings to john"
    re.compile(rf"^{_VERBS}\s+{_CUR}\s*{_AMOUNT}\s*{_CUR}\s+to\s+(?P<target>.+)$"),
    # "send john 500"
    re.compile(rf"^{_VERBS}\s+(?P<target>[a-z0-9+ ]+?)\s+{_CUR}\s*{_AMOUNT}\s*{_CUR}$"),
]
_PHONE = re.compile(r"^(?:\+?254|0)([17]\d{8})$")


@dataclass(frozen=True)
class Intent:
    action: str
    amount: Decimal
    target: str  # raw spoken target: a name or phone number


def normalize_phone(raw: str) -> Optional[str]:
    """Return +254XXXXXXXXX for a valid Kenyan mobile number, else None."""
    digits = re.sub(r"[\s\-]", "", raw)
    m = _PHONE.match(digits)
    return f"+254{m.group(1)}" if m else None


def parse_command(text: str) -> Optional[Intent]:
    cleaned = re.sub(r"\s+", " ", text.strip().lower().rstrip(".!?"))
    for pat in _PATTERNS:
        m = pat.match(cleaned)
        if not m:
            continue
        try:
            amount = Decimal(m.group("amount").replace(",", ""))
        except InvalidOperation:
            return None
        if m.group("k"):
            amount *= 1000
        if amount <= 0:
            return None
        return Intent("transfer", amount, m.group("target").strip())
    return None
