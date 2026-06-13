"""A tiny, offline local web page for non-technical users.

Run it, then open the printed address. A caregiver can bookmark it; the
person at risk just pastes a message and clicks one big button. No
framework, no internet, no data ever leaves the machine — it reuses the
same rule-based ``analyze()`` as the CLI.

    python -m scam_message_analyzer.web
"""

import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from scam_message_analyzer.analyzer import analyze
from scam_message_analyzer.explanations import GENERAL_ADVICE, GREEN_CAVEAT
from scam_message_analyzer.scoring import GREEN, VERDICT_LABEL

_BANNER_COLORS = {
    "red": "#c0392b",
    "yellow": "#b9770e",
    "green": "#1e8449",
}

# Privacy copy for the local server, where these claims are literally true.
# A remote deployment should pass softened wording (see app.py).
LOCAL_INTRO = (
    "Paste the message below and press the button. Nothing you paste leaves "
    "this computer."
)
LOCAL_PRIVACY = (
    "This tool runs entirely on your computer. It uses simple safety rules, "
    "not artificial intelligence, and stores nothing."
)

DEFAULT_TITLE = "Is this a scam?"

# A multi-signal sample shown by the "Try an example" button so first-time
# visitors can see what a check looks like without pasting anything.
EXAMPLE_MESSAGE = (
    "Subject: Urgent: your account is suspended\n\n"
    "Dear Customer,\n\n"
    "We detected unusual activity on your account. Verify your identity "
    "immediately at http://secure-login.verify-account.example or your "
    "account will be permanently closed within 24 hours."
)

# Kept as a separate value (not part of the format template) so its CSS braces
# need no escaping. All styling is inline — no external fonts, CSS, or JS — so
# the page works fully offline and nothing is fetched from the network.
_STYLE = """
  :root {
    --bg: #eef1f7; --card: #fff; --ink: #1b2330; --muted: #5d6b7e;
    --primary: #2563eb; --primary-dark: #1d4ed8; --border: #d4dbe6;
    --accent: #2563eb; --field: #fbfcfe;
  }
  * { box-sizing: border-box; }
  body {
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
    background: var(--bg); color: var(--ink); margin: 0; padding: 28px 16px;
    font-size: 18px; line-height: 1.55;
  }
  .wrap { max-width: 720px; margin: 0 auto; }
  header { text-align: center; margin-bottom: 22px; }
  h1 { font-size: 30px; margin: 0 0 6px; }
  .subtitle { color: var(--muted); margin: 0; }
  .card {
    background: var(--card); border: 1px solid var(--border); border-radius: 16px;
    padding: 22px; box-shadow: 0 8px 28px rgba(20, 32, 64, .07);
  }
  .lead { margin: 0 0 14px; }
  textarea {
    width: 100%; min-height: 200px; font: inherit; padding: 14px;
    border: 2px solid var(--border); border-radius: 12px; resize: vertical;
    background: var(--field); color: var(--ink); caret-color: var(--ink);
  }
  textarea::placeholder { color: var(--muted); opacity: 1; }
  textarea:focus {
    outline: none; border-color: var(--primary);
    box-shadow: 0 0 0 4px rgba(37, 99, 235, .18);
  }
  .actions { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 16px; }
  .btn {
    font-size: 20px; font-weight: 600; padding: 14px 26px; border-radius: 12px;
    border: 2px solid transparent; cursor: pointer; text-decoration: none;
    display: inline-block; text-align: center;
  }
  .btn-primary { background: var(--primary); color: #fff; }
  .btn-primary:hover { background: var(--primary-dark); }
  .btn-secondary { background: var(--card); color: var(--ink); border-color: var(--border); }
  .btn-secondary:hover { background: var(--bg); }
  .btn:focus-visible { outline: 3px solid rgba(37, 99, 235, .5); outline-offset: 2px; }
  .result { margin-top: 4px; }
  .banner {
    color: #fff; padding: 18px 20px; border-radius: 14px; font-size: 26px;
    font-weight: 700; text-align: center; margin: 24px 0 14px;
  }
  .result h2 { font-size: 21px; margin: 6px 0 12px; }
  .findings { list-style: none; padding: 0; margin: 0; }
  .findings li {
    background: var(--card); border: 1px solid var(--border);
    border-left: 6px solid var(--accent); border-radius: 10px;
    padding: 14px 16px; margin-bottom: 12px;
  }
  .advice {
    background: #eef2ff; border: 1px solid #dbe2ff; border-radius: 10px;
    padding: 16px; margin-top: 8px;
  }
  details.how { margin-top: 16px; }
  details.how summary { cursor: pointer; font-weight: 600; color: var(--primary); padding: 6px 0; }
  details.how p { color: var(--muted); margin: 8px 0 0; }
  .notice {
    background: #fff8e1; border: 1px solid #f0d98c; border-radius: 10px;
    padding: 16px; margin-top: 16px;
  }
  .printbtn { margin-top: 12px; }
  .privacy { color: var(--muted); font-size: 15px; text-align: center; margin-top: 26px; }
  @media (max-width: 480px) { .btn { width: 100%; } h1 { font-size: 26px; } }
  .theme-toggle {
    position: fixed; top: 14px; right: 14px; width: 44px; height: 44px;
    border-radius: 50%; border: 1px solid var(--border); background: var(--card);
    color: var(--ink); font-size: 20px; line-height: 1; cursor: pointer;
  }
  .theme-toggle:focus-visible { outline: 3px solid rgba(37, 99, 235, .5); outline-offset: 2px; }
  @media print {
    header .subtitle, .card, .privacy, .printbtn, .theme-toggle { display: none; }
    body { background: #fff; padding: 0; }
  }
  :root[data-theme="dark"] {
    --bg: #11151c; --card: #1b2230; --ink: #e7ecf3; --muted: #9aa7b8;
    --primary: #3b82f6; --primary-dark: #2563eb; --border: #2c3647;
    --field: #141b26;
  }
  :root[data-theme="dark"] .advice { background: #1e2a44; border-color: #2c3b5a; }
  :root[data-theme="dark"] .notice { background: #2a2410; border-color: #5a4a1e; }
"""

# Theme scripts kept as separate values (like _STYLE) so their JS braces are not
# treated as format fields. The head script sets the saved/system theme before
# first paint (no flash); the toggle script flips and persists the choice.
_HEAD_SCRIPT = """<script>
(function () {
  try {
    var t = localStorage.getItem('theme');
    if (t !== 'dark' && t !== 'light') {
      t = window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches
        ? 'dark' : 'light';
    }
    document.documentElement.setAttribute('data-theme', t);
  } catch (e) {}
})();
</script>"""

_TOGGLE_SCRIPT = """<script>
(function () {
  var b = document.getElementById('themeToggle');
  if (!b) return;
  function sync() {
    var dark = document.documentElement.getAttribute('data-theme') === 'dark';
    b.textContent = dark ? '☀️' : '\U0001F319';
    b.setAttribute('aria-pressed', dark);
  }
  sync();
  b.addEventListener('click', function () {
    var dark = document.documentElement.getAttribute('data-theme') === 'dark';
    var next = dark ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    try { localStorage.setItem('theme', next); } catch (e) {}
    sync();
  });
})();
</script>"""

_PAGE = """\
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'><text y='14' font-size='14'>\U0001F6E1️</text></svg>">
{head_script}
<style>{style}</style>
</head>
<body>
<div class="wrap">
  <button id="themeToggle" class="theme-toggle" type="button"
          aria-label="Switch between light and dark mode">\U0001F319</button>
  <header>
    <h1>\U0001F6E1️ Is this email or text a scam?</h1>
    <p class="subtitle">Paste a suspicious message and check it in one click.</p>
  </header>
  <main class="card">
    <p class="lead">{intro}</p>
    <form method="post" action="/#result">
      <textarea name="message" aria-label="Suspicious message to check"
                placeholder="Paste the suspicious email or text here..."
                required autofocus>{message}</textarea>
      <div class="actions">
        <button class="btn btn-primary" type="submit">Check this message</button>
        <a class="btn btn-secondary" href="/?example=1#result" role="button">Try an example</a>
        <a class="btn btn-secondary" href="/" role="button">Clear</a>
      </div>
    </form>
    <details class="how">
      <summary>How does this work?</summary>
      <p>This tool checks your message against a fixed list of known scam
      warning signs. It does not use artificial intelligence and never sends
      your message anywhere — the same message always gets the same answer.</p>
    </details>
  </main>
  <section class="result" id="result" aria-live="polite">{result}</section>
  <p class="privacy">{privacy}</p>
</div>
{toggle_script}
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
        parts.append("<h2>Here's what looks suspicious:</h2>")
        parts.append('<ul class="findings" style="--accent:{}">'.format(color))
        for message in report.messages:
            parts.append("<li>{}</li>".format(html.escape(message)))
        parts.append("</ul>")
    advice = GREEN_CAVEAT if report.verdict == GREEN else GENERAL_ADVICE
    parts.append('<p class="advice">{}</p>'.format(html.escape(advice)))
    parts.append(
        '<button type="button" class="btn btn-secondary printbtn" '
        'onclick="window.print()">Print or save this result</button>'
    )
    return "\n".join(parts)


def render_page(
    message="", result="", intro=LOCAL_INTRO, privacy=LOCAL_PRIVACY, title=DEFAULT_TITLE
):
    return _PAGE.format(
        style=_STYLE,
        head_script=_HEAD_SCRIPT,
        toggle_script=_TOGGLE_SCRIPT,
        title=html.escape(title),
        message=html.escape(message),
        result=result,
        intro=html.escape(intro),
        privacy=html.escape(privacy),
    )


def render_for(message, intro=LOCAL_INTRO, privacy=LOCAL_PRIVACY):
    """Analyze ``message`` and render the full page, with the verdict echoed in
    the browser tab title. Shared by the POST handler and the example link."""

    if not message.strip():
        return render_page(
            result='<p class="notice">Please paste a message above first.</p>',
            intro=intro,
            privacy=privacy,
        )

    report = analyze(message)
    title = "{} — {}".format(VERDICT_LABEL[report.verdict], DEFAULT_TITLE)
    return render_page(
        message=message,
        result=render_result(report),
        intro=intro,
        privacy=privacy,
        title=title,
    )


class _Handler(BaseHTTPRequestHandler):
    def _send(self, body):
        encoded = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        query = parse_qs(urlsplit(self.path).query)
        if "example" in query:
            self._send(render_for(EXAMPLE_MESSAGE))
        else:
            self._send(render_page())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", "replace")
        message = parse_qs(raw).get("message", [""])[0]
        self._send(render_for(message))

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
