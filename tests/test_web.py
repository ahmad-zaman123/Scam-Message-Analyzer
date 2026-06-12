"""Tests for the local web page rendering. No server or network needed."""

import unittest

from scam_message_analyzer.analyzer import analyze
from scam_message_analyzer.web import render_page, render_result

SCAM = (
    "From: PayPal <service@paypa1-secure.ru>\n"
    "Subject: suspended\n\n"
    "Dear Customer, verify immediately or your account will be closed. "
    "Send your password."
)


class RenderResultTests(unittest.TestCase):
    def test_banner_reflects_verdict(self):
        result = render_result(analyze(SCAM))
        self.assertIn("LIKELY A SCAM", result)
        self.assertIn("banner", result)

    def test_lists_findings(self):
        result = render_result(analyze(SCAM))
        self.assertIn("<li>", result)


class RenderPageTests(unittest.TestCase):
    def test_escapes_user_input(self):
        page = render_page(message="<script>alert(1)</script>")
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)

    def test_empty_page_has_form(self):
        page = render_page()
        self.assertIn("<form", page)
        self.assertIn("textarea", page)


if __name__ == "__main__":
    unittest.main()
