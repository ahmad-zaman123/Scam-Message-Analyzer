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


class HomographInEmailBodyTests(unittest.TestCase):
    # "аррle.com" with Cyrillic а (U+0430) and р (U+0440), built from code
    # points so the test file's own encoding can't mask the bug.
    CYRILLIC = chr(0x0430) + chr(0x0440) + chr(0x0440) + "le.com"

    def _email(self):
        return (
            "From: support@" + self.CYRILLIC + "\n"
            "Subject: Apple Security Alert\n\n"
            "Your Apple ID has been locked.\n\n"
            "Visit:\nhttps://" + self.CYRILLIC + "/login\n\nThank you.\n"
        )

    def test_cyrillic_url_in_email_body_is_detected(self):
        # Regression: email bodies were round-tripped through raw-unicode-escape,
        # turning Cyrillic into literal "\\uXXXX" and hiding the homograph.
        report = analyze(self._email())
        self.assertIn("homograph_domain", {f.code for f in report.findings})
        self.assertEqual(report.verdict, "red")


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

    def test_claim_your_refund_flags(self):
        self.assertIn("lottery_prize", codes("Claim your refund here: https://x.test"))

    def test_legit_processed_refund_does_not_flag(self):
        text = "Your refund of $24.00 has been processed and posts in 3-5 days."
        self.assertNotIn("lottery_prize", codes(text))


class ExpiryUrgencyTests(unittest.TestCase):
    def test_offer_expires_today_flags(self):
        self.assertIn("urgency_pressure", codes("Offer expires today. Act fast!"))

    def test_tax_refund_message_is_red(self):
        msg = (
            "Subject: Tax Refund\n\nCongratulations!\n\n"
            "Claim your refund here:\nhttps://bit.ly/3ABCxyz\n\nOffer expires today."
        )
        self.assertEqual(analyze(msg).verdict, "red")


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

    def test_archive_with_lure_is_red(self):
        msg = "Subject: Payroll\n\nAttached is your updated payroll.\n\nPayroll.zip"
        self.assertEqual(analyze(msg).verdict, "red")

    def test_archive_without_lure_stays_yellow(self):
        msg = "Hey, here are the holiday pictures I promised. vacation-photos.zip"
        self.assertEqual(analyze(msg).verdict, "yellow")


class DeceptiveDomainTests(unittest.TestCase):
    PHISH = (
        "URGENT: Your bank account has been suspended.\n"
        "Verify your identity immediately:\n"
        "http://secure-bank-login.verify-account.example\n"
        "Failure to verify within 24 hours will result in permanent closure."
    )

    def test_reported_phishing_is_red(self):
        self.assertEqual(analyze(self.PHISH).verdict, "red")

    def test_lure_word_domain_flags(self):
        self.assertIn("deceptive_domain", codes(self.PHISH))

    def test_legit_brand_subdomain_does_not_flag(self):
        # Registered domain is google.com; "accounts"/"signin" are subdomains.
        text = "Sign in at https://accounts.google.com/signin to continue."
        self.assertNotIn("deceptive_domain", codes(text))

    def test_substring_name_does_not_flag(self):
        # "accountingfirm" must not match the whole-label word "account".
        text = "Your invoice is at https://accountingfirm.com/portal"
        self.assertNotIn("deceptive_domain", codes(text))

    def test_single_lure_word_without_hyphen_does_not_flag(self):
        self.assertNotIn("deceptive_domain", codes("Get help at https://support.com"))


class CredentialLureTests(unittest.TestCase):
    def test_verify_identity_with_link_flags(self):
        text = "Please verify your identity here: https://forms.gle/abc123"
        self.assertIn("credential_lure", codes(text))

    def test_no_link_does_not_flag(self):
        text = "Please verify your identity by visiting our branch in person."
        self.assertNotIn("credential_lure", codes(text))


class WireAndSecrecyTests(unittest.TestCase):
    BEC = (
        "Subject: Confidential Payment\n\n"
        "Please wire $18,750 today to the account below.\n\n"
        "Do not discuss this with anyone.\n\nThis is confidential.\n\n"
        "Bank: ABC Bank\nAccount: 123456789"
    )

    def test_bec_message_is_red(self):
        self.assertEqual(analyze(self.BEC).verdict, "red")

    def test_wire_amount_flags_sensitive_request(self):
        self.assertIn("sensitive_request", codes("Please wire $18,750 today."))

    def test_secrecy_pressure_flags(self):
        self.assertIn("secrecy_pressure", codes("Do not discuss this with anyone."))

    def test_confidential_footer_does_not_flag_secrecy(self):
        text = "This email and its attachments are confidential and intended only for you."
        self.assertNotIn("secrecy_pressure", codes(text))

    def test_wireless_does_not_match_wire(self):
        self.assertNotIn("sensitive_request", codes("Your wireless bill is ready."))


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
