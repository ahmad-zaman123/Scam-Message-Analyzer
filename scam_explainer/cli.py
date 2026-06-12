"""Command-line entry point.

Usage:
    python -m scam_explainer path/to/email.txt
    python -m scam_explainer screenshot.png
    cat email.txt | python -m scam_explainer
"""

import sys

from scam_explainer.analyzer import analyze, format_report
from scam_explainer.ocr import (
    OcrError,
    OcrUnavailable,
    decode_qr_urls,
    image_to_text,
    is_image_path,
)


def _read_input(argv):
    if not argv or argv[0] in ("-", "--stdin"):
        return sys.stdin.read()

    path = argv[0]
    if is_image_path(path):
        text = image_to_text(path)
        qr_urls = decode_qr_urls(path)
        if qr_urls:
            text += "\n" + "\n".join(
                "Link from QR code: " + url for url in qr_urls
            )
        return text
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv

    try:
        raw = _read_input(argv)
    except OcrUnavailable as error:
        print(str(error), file=sys.stderr)
        return 3
    except (OcrError, OSError) as error:
        print("Could not read that file: {}".format(error), file=sys.stderr)
        return 2

    if not raw.strip():
        print("Nothing to check. Paste an email, or pass a file or screenshot.", file=sys.stderr)
        return 2

    report = analyze(raw)
    print(format_report(report, use_color=sys.stdout.isatty()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
