"""Orchestrate parsing, detection, scoring, and explanation."""

import email
import re
from dataclasses import dataclass
from email.utils import parseaddr

from scam_message_analyzer import checks
from scam_message_analyzer.explanations import GENERAL_ADVICE, GREEN_CAVEAT, explain
from scam_message_analyzer.scoring import GREEN, VERDICT_LABEL, score


@dataclass
class Report:
    verdict: str
    weight: int
    findings: list
    messages: list


def _domain_of(address):
    _, addr = parseaddr(address or "")
    return addr.split("@")[-1].lower() if "@" in addr else ""


def _parse(raw):
    """Split raw input into headers and HTML/plain bodies.

    Accepts a full raw email (with headers) or just pasted body text.
    """

    headers = {"from_name": "", "from_domain": "", "reply_to_domain": ""}
    html_body = ""
    plain_body = raw
    attachments = []

    looks_like_email = bool(re.match(r"(?im)^(from|subject|to|date):", raw or ""))
    if looks_like_email:
        message = email.message_from_string(raw)
        name, addr = parseaddr(message.get("From", ""))
        headers["from_name"] = name
        headers["from_domain"] = addr.split("@")[-1].lower() if "@" in addr else ""
        headers["reply_to_domain"] = _domain_of(message.get("Reply-To", ""))

        plain_parts = []
        html_parts = []
        for part in message.walk():
            if part.is_multipart():
                continue
            filename = part.get_filename()
            if filename:
                attachments.append(filename)
            content_type = part.get_content_type()
            try:
                payload = part.get_payload(decode=True)
                text = payload.decode(part.get_content_charset() or "utf-8", "replace")
            except (UnicodeDecodeError, LookupError, AttributeError):
                text = part.get_payload() or ""
            if content_type == "text/html":
                html_parts.append(text)
            elif content_type == "text/plain":
                plain_parts.append(text)
        html_body = "\n".join(html_parts)
        plain_body = "\n".join(plain_parts) if plain_parts else ""
    elif "<a " in (raw or "").lower() or "<html" in (raw or "").lower():
        html_body = raw
        plain_body = ""

    # A body can carry anchor tags even inside a text/plain part; make sure
    # those links still get parsed for the text-vs-destination check.
    if not html_body and "<a " in (plain_body or "").lower():
        html_body = plain_body

    return headers, html_body, plain_body, attachments


def analyze(raw):
    """Analyze a raw email or message and return a :class:`Report`."""

    headers, html_body, plain_body, attachments = _parse(raw)
    links = checks.extract_links(html_body, plain_body)
    body_text = " ".join(filter(None, [checks.strip_html(html_body), plain_body]))

    findings = []
    for check in checks.ALL_CHECKS:
        findings.extend(
            check(
                links=links,
                headers=headers,
                body_text=body_text,
                attachments=attachments,
            )
        )

    # Show the most serious signals first; stable so detector order is kept
    # within a severity level.
    findings.sort(key=lambda finding: finding.weight, reverse=True)

    verdict, weight = score(findings)
    messages = [explain(finding) for finding in findings]
    return Report(verdict=verdict, weight=weight, findings=findings, messages=messages)


_ANSI = {
    "red": "\033[1;31m",
    "yellow": "\033[1;33m",
    "green": "\033[1;32m",
}
_ANSI_RESET = "\033[0m"


def _verdict_line(verdict, use_color):
    label = VERDICT_LABEL[verdict]
    if use_color and verdict in _ANSI:
        return "{}{}{}".format(_ANSI[verdict], label, _ANSI_RESET)
    return label


def format_report(report, use_color=False):
    """Render a report as plain text for the terminal."""

    lines = [_verdict_line(report.verdict, use_color), ""]
    if report.messages:
        lines.append("Here's what looks suspicious:")
        for message in report.messages:
            lines.append("  • " + message)
        lines.append("")
    if report.verdict == GREEN:
        lines.append(GREEN_CAVEAT)
    else:
        lines.append(GENERAL_ADVICE)
    return "\n".join(lines)
