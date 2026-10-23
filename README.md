# 🎙️ VoicePay

Voice-initiated payments with **layered verification** and **rule-based fraud detection**.
Say *"send 500 to John"* and VoicePay turns it into a pending transaction, scores its risk,
asks for the right level of proof, and only then moves money.

> **Sandbox project.** Money movement runs against a mock bank (`MockBank`). No real funds move.
> Real providers plug in through a single adapter interface (see [Bank integration](#bank-integration)).

## How it works

```
 voice (transcribed text)
        │
        ▼
 ┌──────────────┐   ┌───────────────┐   ┌──────────────────────┐   ┌────────────┐
 │ Intent parser│──▶│ Fraud scoring │──▶│ Verification policy  │──▶│ Bank adapter│
 │ "send 500 to │   │ rules → score │   │ ALLOW  : PIN         │   │ idempotent  │
 │  john"       │   │               │   │ STEP_UP: PIN + OTP   │   │ transfer    │
 └──────────────┘   └───────────────┘   │ BLOCK  : rejected    │   └────────────┘
                                        └──────────────────────┘
```

A voice command **never moves money by itself**. It only creates a pending transaction.
Money moves after a separate verification call.

## Security design

| Concern | Approach |
|---|---|
| Spoofed or misheard voice | Voice only *proposes* a payment; a PIN is always required to confirm |
| Stolen session / account takeover | Risky payments (new payee, unusual amount, odd hours) need a one-time code sent out-of-band |
| Brute force | 3 wrong attempts cancel the transaction; OTPs expire in 5 minutes |
| Double charges | Every transfer carries an idempotency key; replays return the original reference |
| Credential storage | PINs hashed with PBKDF2-SHA256 (200k rounds) and a per-user salt; OTPs stored only as HMAC |
| Sessions | Signed, expiring bearer tokens; constant-time comparisons throughout |
| Data isolation | Every transaction query is scoped to the authenticated user |
| Auditability | Append-only `audit` table records logins, decisions and failures |

## Fraud rules

| Rule | Risk points |
|---|---|
| Exceeds daily limit | +100 (blocked) |
| New payee | +30 |
| Amount ≥ 5× your usual transfer | +30 |
| 3+ transactions in 10 minutes | +30 |
| Recent failed verification | +25 |
| High-value transfer (≥ KES 20,000) | +20 |
| Unusual hour (00:00–05:00) | +15 |

`< 30` → PIN only · `30–69` → PIN + OTP · `≥ 70` → blocked.

## Run it

Requires Python 3.9+. **No third-party dependencies.**

```bash
python -m voicepay                      # starts on http://127.0.0.1:8000
python -m unittest discover -s tests    # run the test suite
```

Then open **http://127.0.0.1:8000** for the demo page: register, save a contact, click the 🎤 and say *"send 500 to John"* (voice works in Chrome and Edge; there's a typing fallback). OTP codes are printed to the server console in sandbox mode (SMS in production).

### Example session

```bash
curl -X POST localhost:8000/register -d '{"username":"alice","pin":"4321"}'
TOKEN=$(curl -s -X POST localhost:8000/login -d '{"username":"alice","pin":"4321"}' | python -c "import sys,json;print(json.load(sys.stdin)['token'])")

curl -X POST localhost:8000/contacts -H "Authorization: Bearer $TOKEN" -d '{"name":"John","phone":"0711111111"}'
curl -X POST localhost:8000/voice/command -H "Authorization: Bearer $TOKEN" -d '{"text":"send 500 to john"}'
# -> {"transaction_id": "...", "status": "AWAITING_VERIFICATION", "requires_otp": false, ...}
curl -X POST localhost:8000/transactions/<id>/verify -H "Authorization: Bearer $TOKEN" -d '{"pin":"4321"}'
```

## API

| Method | Path | Purpose |
|---|---|---|
| POST | `/register`, `/login` | Create account, get token |
| POST | `/contacts` | Save a payee by name |
| POST | `/voice/command` | Parse a command, score risk, create a pending transaction |
| POST | `/transactions/<id>/verify` | Confirm with PIN (+ OTP) and execute |
| GET | `/transactions` | Transaction history |

## Bank integration

`voicepay/bank.py` defines `BankAdapter.transfer(idempotency_key, user_id, to_phone, amount)`.
`MockBank` implements it for the sandbox. `DarajaAdapter` is a stub for M-Pesa Daraja (B2C).
A real integration needs provider credentials, a signed request, and a callback endpoint that
confirms the final result, all of which stay inside the adapter.

## Roadmap

- Server-side speech-to-text (Whisper) as an alternative to the browser's Web Speech API
- Voice liveness / speaker verification as an extra signal
- Daraja adapter with webhook confirmation
- Move to FastAPI + PostgreSQL, add rate limiting and TLS termination
- ML anomaly scoring alongside the rule engine
- Mobile client with push-based approvals

## Project layout

```
voicepay/
  parser.py    command → intent
  fraud.py     risk rules and decision policy
  security.py  PIN hashing, OTP, signed tokens
  bank.py      adapter interface, MockBank, Daraja stub
  service.py   business logic
  server.py    JSON HTTP API + serves the demo page
  static/      demo web page with microphone button
tests/         17 tests: parser, fraud rules, security, full API flows
```
