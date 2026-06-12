"""Tests for the extended detector pack."""

import unittest
from unittest import mock

from scam_message_analyzer import ocr
from scam_message_analyzer.analyzer import analyze


def codes(text):
    return {finding.code for finding in analyze(text).findings}


class HomographTests(unittest.TestCase):
    def test_cyrillic_lookalike_flags(self):
        # "аpple" here starts with a Cyrillic 'а' (U+0430).
        html = '<a href="http://аpple.com/login">sign in</a>'
        self.assertIn("homograph_domain", codes(html))

    def test_plain_ascii_domain_does_not_flag(self):
        html = '<a href="http://apple.com/login">sign in</a>'
        self.assertNotIn("homograph_domain", codes(html))


class TechSupportTests(unittest.TestCase):
    def test_infected_computer_flags(self):
        text = "Warning: your computer is infected. Microsoft support detected a virus."
        self.assertIn("tech_support_scam", codes(text))


class CallNumberTests(unittest.TestCase):
    def test_phone_with_call_flags(self):
        text = "Please call us immediately at 1-800-555-0199 to restore service."
        self.assertIn("call_a_number", codes(text))

    def test_phone_without_call_context_does_not_flag(self):
        text = "Our office is located at 123 Main Street, suite 4567890."
        self.assertNotIn("call_a_number", codes(text))


class LotteryTests(unittest.TestCase):
    def test_lottery_win_flags(self):
        text = "Congratulations! You have won the national lottery jackpot."
        self.assertIn("lottery_prize", codes(text))

    def test_large_money_amount_flags(self):
        text = "You are entitled to a transfer of $4,500,000 from an unnamed estate."
        self.assertIn("lottery_prize", codes(text))


class AttachmentTests(unittest.TestCase):
    def test_executable_attachment_in_email_flags(self):
        raw = (
            "From: billing@example.com\n"
            'Content-Type: multipart/mixed; boundary="b"\n\n'
            "--b\nContent-Type: text/plain\n\nSee attached invoice.\n"
            "--b\nContent-Type: application/octet-stream\n"
            'Content-Disposition: attachment; filename="invoice.pdf.exe"\n\n'
            "x\n--b--\n"
        )
        found = {f.code for f in analyze(raw).findings}
        self.assertIn("risky_attachment", found)

    def test_mentioned_html_attachment_flags(self):
        text = "Open the attached document secure_form.html to continue."
        self.assertIn("risky_attachment", codes(text))


class QrDecodeTests(unittest.TestCase):
    def test_no_zbar_returns_empty(self):
        with mock.patch("scam_message_analyzer.ocr.shutil.which", return_value=None):
            self.assertEqual(ocr.decode_qr_urls("shot.png"), [])

    def test_extracts_urls_from_output(self):
        fake = mock.Mock(returncode=0, stdout="http://bit.ly/x\nplain text\n", stderr="")
        with mock.patch("scam_message_analyzer.ocr.shutil.which", return_value="/usr/bin/zbarimg"), \
                mock.patch("scam_message_analyzer.ocr.os.path.isfile", return_value=True), \
                mock.patch("scam_message_analyzer.ocr.subprocess.run", return_value=fake):
            self.assertEqual(ocr.decode_qr_urls("shot.png"), ["http://bit.ly/x"])


if __name__ == "__main__":
    unittest.main()
