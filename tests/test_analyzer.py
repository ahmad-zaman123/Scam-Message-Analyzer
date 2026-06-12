"""Tests for the detection pipeline. No network, no API keys needed."""

import unittest

from scam_message_analyzer.analyzer import analyze
from scam_message_analyzer.scoring import GREEN, RED, YELLOW

SCAM_EMAIL = """\
From: PayPal Security <service@paypa1-secure.ru>
Reply-To: refunds@mail-helpdesk.net
Subject: Your account has been suspended

Dear Customer,

We noticed unusual activity on your account. Your account has been suspended.
You must verify your identity immediately or your account will be closed.

<a href="http://198.51.100.23/login">Log in to paypal.com</a>

Please confirm your password and card verification code to restore access.
"""

LEGIT_EMAIL = """\
From: Aunt Carol <carol@gmail.com>
Subject: Lunch on Sunday?

Hi Sam,

Are you free for lunch this Sunday around noon? Let me know.

Love,
Carol
"""


class AnalyzeScamTests(unittest.TestCase):
    def setUp(self):
        self.report = analyze(SCAM_EMAIL)
        self.codes = {finding.code for finding in self.report.findings}

    def test_verdict_is_red(self):
        self.assertEqual(self.report.verdict, RED)

    def test_detects_link_text_mismatch(self):
        self.assertIn("link_text_mismatch", self.codes)

    def test_detects_raw_ip_url(self):
        self.assertIn("raw_ip_url", self.codes)

    def test_detects_sender_brand_mismatch(self):
        self.assertIn("sender_brand_mismatch", self.codes)

    def test_detects_reply_to_mismatch(self):
        self.assertIn("reply_to_mismatch", self.codes)

    def test_detects_urgency(self):
        self.assertIn("urgency_pressure", self.codes)

    def test_detects_sensitive_request(self):
        self.assertIn("sensitive_request", self.codes)

    def test_detects_generic_greeting(self):
        self.assertIn("generic_greeting", self.codes)

    def test_messages_are_human_readable(self):
        self.assertTrue(all(self.report.messages))


class AnalyzeLegitTests(unittest.TestCase):
    def test_clean_email_is_green(self):
        report = analyze(LEGIT_EMAIL)
        self.assertEqual(report.verdict, GREEN)
        self.assertEqual(report.findings, [])


class LookalikeDomainTests(unittest.TestCase):
    def test_brand_in_unrelated_domain_flags(self):
        report = analyze('<a href="http://paypal.com.secure-login.ru/x">click</a>')
        codes = {finding.code for finding in report.findings}
        self.assertIn("lookalike_domain", codes)

    def test_shortener_is_flagged_yellow_or_red(self):
        report = analyze("Click here: https://bit.ly/3xYz to claim your prize")
        self.assertIn(report.verdict, (YELLOW, RED))


if __name__ == "__main__":
    unittest.main()
