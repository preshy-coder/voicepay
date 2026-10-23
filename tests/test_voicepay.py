import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from datetime import datetime
from decimal import Decimal
from http.server import HTTPServer

os.environ["VOICEPAY_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")

from voicepay import fraud, parser, security, server, service  # noqa: E402

SENT = []


class ParserTests(unittest.TestCase):
    def test_variants(self):
        for text, amount, target in [
            ("Send 500 shillings to John", 500, "john"),
            ("pay 1,200 to 0712345678", 1200, "0712345678"),
            ("transfer 2k to mary wanjiku.", 2000, "mary wanjiku"),
            ("send john 750", 750, "john"),
        ]:
            i = parser.parse_command(text)
            self.assertEqual((i.amount, i.target), (Decimal(amount), target), text)

    def test_rejects_garbage(self):
        for text in ["hello there", "send to john", "send 0 to john", "send -5 to john"]:
            self.assertIsNone(parser.parse_command(text), text)

    def test_phone(self):
        self.assertEqual(parser.normalize_phone("0712 345 678"), "+254712345678")
        self.assertEqual(parser.normalize_phone("+254112345678"), "+254112345678")
        self.assertIsNone(parser.normalize_phone("12345"))


class SecurityTests(unittest.TestCase):
    def test_token_roundtrip_expiry_and_tamper(self):
        t = security.make_token(7)
        self.assertEqual(security.read_token(t), 7)
        self.assertIsNone(security.read_token(t + "x"))
        self.assertIsNone(security.read_token(security.make_token(7, ttl=-10)))

    def test_pin_hash(self):
        salt = security.new_salt()
        h = security.hash_secret("1234", salt)
        self.assertTrue(security.check_secret("1234", salt, h))
        self.assertFalse(security.check_secret("1235", salt, h))


class FraudTests(unittest.TestCase):
    NOW = datetime(2026, 10, 22, 14, 0)

    def test_clean_known_payee_allowed(self):
        r = fraud.assess(Decimal(500), True, [], Decimal(50000), self.NOW)
        self.assertEqual(r.decision, "ALLOW")

    def test_new_payee_large_night_is_stepped_up(self):
        r = fraud.assess(Decimal(25000), False, [], Decimal(50000), datetime(2026, 10, 22, 2, 0))
        self.assertEqual(r.decision, "BLOCK" if r.score >= 70 else "STEP_UP")
        self.assertGreaterEqual(r.score, 30)

    def test_over_limit_blocked(self):
        r = fraud.assess(Decimal(60000), True, [], Decimal(50000), self.NOW)
        self.assertEqual(r.decision, "BLOCK")

    def test_velocity(self):
        hist = [fraud.TxnRecord(Decimal(100), self.NOW, "COMPLETED") for _ in range(3)]
        r = fraud.assess(Decimal(100), True, hist, Decimal(50000), self.NOW)
        self.assertIn("many transactions in the last 10 minutes", r.reasons)


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        server.Handler.notify = staticmethod(lambda uid, otp: SENT.append(otp))
        cls.httpd = HTTPServer(("127.0.0.1", 0), server.Handler)
        cls.base = f"http://127.0.0.1:{cls.httpd.server_port}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def call(self, method, path, body=None, token=None):
        req = urllib.request.Request(self.base + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None)
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    def user(self, name):
        self.call("POST", "/register", {"username": name, "pin": "4321"})
        return self.call("POST", "/login", {"username": name, "pin": "4321"})[1]["token"]

    def test_serves_demo_page(self):
        with urllib.request.urlopen(self.base + "/") as r:
            html = r.read().decode()
            self.assertEqual(r.status, 200)
            self.assertIn("VoicePay", html)
            self.assertIn("Content-Security-Policy", r.headers)

    def test_requires_auth(self):
        self.assertEqual(self.call("GET", "/transactions")[0], 401)

    def test_known_contact_flow_pin_only(self):
        tok = self.user("alice")
        self.call("POST", "/contacts", {"name": "John", "phone": "0711111111"}, tok)
        s, txn = self.call("POST", "/voice/command", {"text": "send 500 to john"}, tok)
        self.assertEqual((s, txn["status"], txn["requires_otp"]), (201, "AWAITING_VERIFICATION", False))
        path = f"/transactions/{txn['transaction_id']}/verify"
        self.assertEqual(self.call("POST", path, {"pin": "0000"}, tok)[0], 401)
        s, done = self.call("POST", path, {"pin": "4321"}, tok)
        self.assertEqual((s, done["status"]), (200, "COMPLETED"))
        # replay is idempotent: same reference, no double charge
        s2, again = self.call("POST", path, {"pin": "4321"}, tok)
        self.assertEqual(again["reference"], done["reference"])

    def test_new_payee_needs_otp(self):
        tok = self.user("bob")
        SENT.clear()
        s, txn = self.call("POST", "/voice/command", {"text": "send 800 to 0722222222"}, tok)
        self.assertTrue(txn["requires_otp"])
        path = f"/transactions/{txn['transaction_id']}/verify"
        self.assertEqual(self.call("POST", path, {"pin": "4321"}, tok)[0], 401)  # missing code
        self.assertEqual(self.call("POST", path, {"pin": "4321", "otp": SENT[-1]}, tok)[1]["status"], "COMPLETED")

    def test_over_limit_is_blocked_and_cannot_be_verified(self):
        tok = self.user("carol")
        s, txn = self.call("POST", "/voice/command", {"text": "send 90000 to 0733333333"}, tok)
        self.assertEqual(txn["status"], "BLOCKED")
        path = f"/transactions/{txn['transaction_id']}/verify"
        self.assertEqual(self.call("POST", path, {"pin": "4321"}, tok)[0], 409)

    def test_three_failures_cancel(self):
        tok = self.user("dave")
        self.call("POST", "/contacts", {"name": "Sam", "phone": "0744444444"}, tok)
        _, txn = self.call("POST", "/voice/command", {"text": "send 100 to sam"}, tok)
        path = f"/transactions/{txn['transaction_id']}/verify"
        for _ in range(3):
            self.call("POST", path, {"pin": "9999"}, tok)
        self.assertEqual(self.call("POST", path, {"pin": "4321"}, tok)[0], 409)

    def test_users_cannot_touch_each_others_transactions(self):
        a, b = self.user("erin"), self.user("frank")
        _, txn = self.call("POST", "/voice/command", {"text": "send 100 to 0755555555"}, a)
        s, _ = self.call("POST", f"/transactions/{txn['transaction_id']}/verify", {"pin": "4321"}, b)
        self.assertEqual(s, 404)

    def test_insufficient_funds(self):
        from voicepay import db
        tok = self.user("gina")
        self.call("POST", "/contacts", {"name": "Ann", "phone": "0766666666"}, tok)
        with db.connect() as conn:
            conn.execute("UPDATE users SET balance=50 WHERE username='gina'")
        _, txn = self.call("POST", "/voice/command", {"text": "send 100 to ann"}, tok)
        s, body = self.call("POST", f"/transactions/{txn['transaction_id']}/verify", {"pin": "4321"}, tok)
        self.assertEqual((s, body["error"]), (422, "insufficient funds"))


if __name__ == "__main__":
    unittest.main()
