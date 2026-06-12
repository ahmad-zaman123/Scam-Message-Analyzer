"""Tests for the OCR layer and image routing in the CLI.

These run without tesseract installed by faking the binary lookup, so the
suite stays fully offline and dependency-free.
"""

import unittest
from unittest import mock

from scam_explainer import ocr
from scam_explainer.cli import main


class IsImagePathTests(unittest.TestCase):
    def test_recognizes_image_extensions(self):
        for path in ("a.png", "b.JPG", "c.jpeg", "shot.webp"):
            self.assertTrue(ocr.is_image_path(path), path)

    def test_rejects_non_images(self):
        for path in ("email.txt", "message.eml", "notes"):
            self.assertFalse(ocr.is_image_path(path), path)


class ImageToTextTests(unittest.TestCase):
    def test_missing_binary_raises_unavailable(self):
        with mock.patch("scam_explainer.ocr.shutil.which", return_value=None):
            with self.assertRaises(ocr.OcrUnavailable):
                ocr.image_to_text("shot.png")

    def test_missing_file_raises_error(self):
        with mock.patch("scam_explainer.ocr.shutil.which", return_value="/usr/bin/tesseract"):
            with self.assertRaises(ocr.OcrError):
                ocr.image_to_text("does-not-exist.png")

    def test_returns_text_on_success(self):
        fake = mock.Mock(returncode=0, stdout="verify your account now", stderr="")
        with mock.patch("scam_explainer.ocr.shutil.which", return_value="/usr/bin/tesseract"), \
                mock.patch("scam_explainer.ocr.os.path.isfile", return_value=True), \
                mock.patch("scam_explainer.ocr.subprocess.run", return_value=fake):
            self.assertEqual(ocr.image_to_text("shot.png"), "verify your account now")


class NormalizeOcrTextTests(unittest.TestCase):
    def test_repairs_spaced_scheme(self):
        self.assertEqual(
            ocr.normalize_ocr_text("go to http: // example.com now"),
            "go to http://example.com now",
        )

    def test_repairs_spaced_tld(self):
        self.assertEqual(
            ocr.normalize_ocr_text("http://bit. ly/abc"),
            "http://bit.ly/abc",
        )


class CliImageRoutingTests(unittest.TestCase):
    def test_cli_runs_analysis_on_ocr_text(self):
        scam_text = (
            "Dear Customer, your account has been suspended. Verify immediately "
            "or it will be closed. Send your password."
        )
        with mock.patch("scam_explainer.cli.is_image_path", return_value=True), \
                mock.patch("scam_explainer.cli.image_to_text", return_value=scam_text):
            self.assertEqual(main(["shot.png"]), 0)

    def test_cli_reports_missing_tesseract(self):
        with mock.patch("scam_explainer.cli.is_image_path", return_value=True), \
                mock.patch(
                    "scam_explainer.cli.image_to_text",
                    side_effect=ocr.OcrUnavailable("install it"),
                ):
            self.assertEqual(main(["shot.png"]), 3)


if __name__ == "__main__":
    unittest.main()
