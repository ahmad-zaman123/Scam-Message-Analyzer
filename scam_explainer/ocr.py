"""Offline OCR for screenshots, via the local ``tesseract`` binary.

Most people who want a message checked have a *screenshot* of a text or
email, not its raw text. This module turns an image into text so the same
detectors can run on it. It shells out to the ``tesseract`` command, so there
is no Python package to install and nothing leaves the machine.
"""

import os
import re
import shutil
import subprocess

# OCR commonly inserts a stray space inside URLs ("http: //", "bit. ly").
# Repair the most frequent cases so link-based checks still fire. Applied
# only to OCR output, never to text the user typed.
_OCR_SCHEME = re.compile(r"(https?):\s*//\s*", re.IGNORECASE)
_OCR_TLD_SPACE = re.compile(
    r"\.\s+(ly|com|net|org|co|io|ru|uk|gov|edu|info|biz|me|app|xyz|online)\b",
    re.IGNORECASE,
)

IMAGE_EXTENSIONS = frozenset(
    {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp"}
)

INSTALL_HINT = (
    "To read screenshots, install Tesseract OCR:\n"
    "  • Ubuntu/Debian:  sudo apt install tesseract-ocr\n"
    "  • macOS (brew):   brew install tesseract\n"
    "  • Windows:        https://github.com/UB-Mannheim/tesseract/wiki"
)


class OcrUnavailable(RuntimeError):
    """Raised when the tesseract binary is not installed."""


class OcrError(RuntimeError):
    """Raised when OCR runs but fails (bad file, unreadable image)."""


def is_image_path(path):
    return os.path.splitext(path)[1].lower() in IMAGE_EXTENSIONS


def tesseract_available():
    return shutil.which("tesseract") is not None


def image_to_text(path):
    """Return the text extracted from an image file.

    Raises :class:`OcrUnavailable` if tesseract is missing, or
    :class:`OcrError` if the file is absent or cannot be read.
    """

    if not tesseract_available():
        raise OcrUnavailable(INSTALL_HINT)
    if not os.path.isfile(path):
        raise OcrError("Image file not found: {}".format(path))

    try:
        result = subprocess.run(
            ["tesseract", path, "stdout"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        raise OcrError("Could not run tesseract: {}".format(error))

    if result.returncode != 0:
        raise OcrError(result.stderr.strip() or "tesseract failed to read the image")
    return normalize_ocr_text(result.stdout)


def normalize_ocr_text(text):
    """Repair common OCR artifacts inside URLs so link checks still fire."""

    text = _OCR_SCHEME.sub(lambda match: match.group(1) + "://", text)
    text = _OCR_TLD_SPACE.sub(lambda match: "." + match.group(1), text)
    return text


def zbar_available():
    return shutil.which("zbarimg") is not None


def decode_qr_urls(path):
    """Best-effort: return any URLs encoded in QR codes in the image.

    "Quishing" scams hide the malicious link inside a QR code so OCR can't see
    it. If the optional ``zbarimg`` tool is missing, this quietly returns an
    empty list — QR support is a bonus, never required.
    """

    if not zbar_available() or not os.path.isfile(path):
        return []
    try:
        result = subprocess.run(
            ["zbarimg", "-q", "--raw", path],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return []

    urls = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if re.match(r"https?://", line, re.IGNORECASE):
            urls.append(line)
    return urls
