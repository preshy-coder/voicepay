import os
import tempfile
import unittest

from voicepay import config, notify
from voicepay.ratelimit import RateLimiter


class RateLimiterTests(unittest.TestCase):
    def test_blocks_after_limit_then_recovers(self):
        rl = RateLimiter(3, 60)
        self.assertTrue(all(rl.allow("a", now=t) for t in (0, 1, 2)))
        self.assertFalse(rl.allow("a", now=3))
        self.assertTrue(rl.allow("b", now=3))      # other keys unaffected
        self.assertTrue(rl.allow("a", now=61))     # window slid past the first hit


class ConfigTests(unittest.TestCase):
    def test_env_file_does_not_override_real_variables(self):
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as f:
            f.write('# comment\nVOICEPAY_TESTKEY="from-file"\nVOICEPAY_OTHER=2\n')
        os.environ["VOICEPAY_OTHER"] = "1"
        config.load_env(f.name)
        self.assertEqual(os.environ["VOICEPAY_TESTKEY"], "from-file")
        self.assertEqual(os.environ["VOICEPAY_OTHER"], "1")

    def test_defaults(self):
        self.assertEqual(config.get_settings().port, 8000)


class NotifyTests(unittest.TestCase):
    def test_unknown_provider_rejected(self):
        os.environ["VOICEPAY_SMS"] = "nope"
        with self.assertRaises(ValueError):
            notify.send_otp(1, "123456")
        os.environ["VOICEPAY_SMS"] = "console"


if __name__ == "__main__":
    unittest.main()