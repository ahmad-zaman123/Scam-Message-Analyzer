"""WSGI entrypoint so the analyzer can be deployed as a web service (e.g. Vercel).

This wraps the same rule-based ``analyze()`` used by the CLI and the local
server, exposing it through the WSGI ``app`` callable that hosting platforms
look for.

Privacy note: when this runs on a remote host, pasted messages are sent to that
server. The bundled local server keeps everything on your own machine and is
the right choice when privacy matters:

    python -m scam_message_analyzer.web
"""

from urllib.parse import parse_qs

from scam_message_analyzer.web import EXAMPLE_MESSAGE, render_for, render_page

# Hosted copy: unlike the local server, pasted text is sent to this server, so
# drop the "stays on your computer" claims and keep only what stays true here.
HOSTED_INTRO = "Paste the message below and press the button."
HOSTED_PRIVACY = (
    "This tool uses simple safety rules, not artificial intelligence, and "
    "stores nothing."
)


def app(environ, start_response):
    """Minimal, dependency-free WSGI app: GET shows the form, POST analyzes."""

    if environ.get("REQUEST_METHOD", "GET").upper() == "POST":
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except (TypeError, ValueError):
            length = 0
        raw = environ["wsgi.input"].read(length).decode("utf-8", "replace")
        message = parse_qs(raw).get("message", [""])[0]
        body = render_for(message, intro=HOSTED_INTRO, privacy=HOSTED_PRIVACY)
    elif "example" in parse_qs(environ.get("QUERY_STRING", "")):
        body = render_for(EXAMPLE_MESSAGE, intro=HOSTED_INTRO, privacy=HOSTED_PRIVACY)
    else:
        body = render_page(intro=HOSTED_INTRO, privacy=HOSTED_PRIVACY)

    encoded = body.encode("utf-8")
    start_response(
        "200 OK",
        [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Content-Length", str(len(encoded))),
        ],
    )
    return [encoded]
