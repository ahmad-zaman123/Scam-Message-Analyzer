"""A tiny, offline local web page for non-technical users.

Run it, then open the printed address. A caregiver can bookmark it; the
person at risk just pastes a message and clicks one big button. No
framework, no internet, no data ever leaves the machine — it reuses the
same rule-based ``analyze()`` as the CLI.

    python -m scam_explainer.web
"""

import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from scam_explainer.analyzer import analyze
from scam_explainer.explanations import GENERAL_ADVICE, GREEN_CAVEAT
from scam_explainer.scoring import GREEN, VERDICT_LABEL

_BANNER_COLORS = {
    "red": "#c0392b",
    "yellow": "#b9770e",
    "green": "#1e8449",
}

_PAGE = """\
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Is this a scam?</title>
<style>
  body {{ font-family: system-ui, Arial, sans-serif; max-width: 720px;
         margin: 0 auto; padding: 24px; font-size: 20px; color: #1a1a1a; }}
  h1 {{ font-size: 30px; }}
  textarea {{ width: 100%; min-height: 220px; font-size: 20px; padding: 12px;
              box-sizing: border-box; border: 2px solid #999; border-radius: 8px; }}
  button {{ font-size: 24px; padding: 16px 32px; margin-top: 16px; border: 0;
            border-radius: 10px; background: #2563eb; color: #fff; cursor: pointer; }}
  .banner {{ color: #fff; padding: 20px; border-radius: 10px; font-size: 28px;
             font-weight: bold; margin: 24px 0; text-align: center; }}
  ul {{ line-height: 1.5; }}
  .advice {{ background: #f1f1f1; padding: 16px; border-radius: 8px; }}
  .privacy {{ color: #666; font-size: 16px; margin-top: 32px; }}
</style>
</head>
<body>
<h1>Is this email or text a scam?</h1>
<p>Paste the message below and press the button. Nothing you paste leaves
this computer.</p>
<form method="post" action="/">
  <textarea name="message" placeholder="Paste the suspicious email or text here..."
            autofocus>{message}</textarea>
  <br><button type="submit">Check this message</button>
</form>
{result}
<p class="privacy">This tool runs entirely on your computer. It uses simple
safety rules, not artificial intelligence, and stores nothing.</p>
</body>
</html>
"""


def render_result(report):
    """Return the HTML fragment for a completed analysis."""

    color = _BANNER_COLORS.get(report.verdict, "#444")
    parts = [
        '<div class="banner" style="background:{}">{}</div>'.format(
            color, html.escape(VERDICT_LABEL[report.verdict])
        )
    ]
    if report.messages:
        parts.append("<h2>Here's what looks suspicious:</h2><ul>")
        for message in report.messages:
            parts.append("<li>{}</li>".format(html.escape(message)))
        parts.append("</ul>")
    advice = GREEN_CAVEAT if report.verdict == GREEN else GENERAL_ADVICE
    parts.append('<p class="advice">{}</p>'.format(html.escape(advice)))
    return "\n".join(parts)


def render_page(message="", result=""):
    return _PAGE.format(message=html.escape(message), result=result)


class _Handler(BaseHTTPRequestHandler):
    def _send(self, body):
        encoded = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        self._send(render_page())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", "replace")
        message = parse_qs(raw).get("message", [""])[0]
        report = analyze(message)
        self._send(render_page(message=message, result=render_result(report)))

    def log_message(self, *args):
        # Stay quiet — no request logging of (possibly personal) content.
        pass


def main(host="127.0.0.1", port=8765):
    server = ThreadingHTTPServer((host, port), _Handler)
    print("Open this in your browser:  http://{}:{}".format(host, port))
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
