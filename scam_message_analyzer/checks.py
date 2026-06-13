"""Deterministic detectors. No network, no AI — pure, testable rules.

Each detector takes the parsed message and returns a list of ``Finding``
objects. Detectors must never raise on malformed input; they simply return
nothing when a signal is absent.
"""

import ipaddress
import re
from html.parser import HTMLParser

from scam_message_analyzer.findings import HIGH, LOW, MEDIUM, Finding

# Common two-part public suffixes, so "bbc.co.uk" -> "bbc.co.uk" not "co.uk".
# A pragmatic subset of the Public Suffix List — enough for brand/shortener
# comparison without a network dependency.
_MULTI_SUFFIXES = frozenset(
    {
        "co.uk",
        "org.uk",
        "gov.uk",
        "ac.uk",
        "me.uk",
        "co.jp",
        "ne.jp",
        "or.jp",
        "com.au",
        "net.au",
        "org.au",
        "co.nz",
        "co.in",
        "co.za",
        "com.br",
        "com.mx",
        "com.sg",
        "com.hk",
    }
)

# Canonical domains for commonly-impersonated brands.
BRANDS = {
    "paypal": "paypal.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "fedex": "fedex.com",
    "ups": "ups.com",
    "usps": "usps.com",
    "dhl": "dhl.com",
    "irs": "irs.gov",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
    "coinbase": "coinbase.com",
}

# Common link-shortening services — they hide the true destination.
SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "rb.gy",
}

# Characters scammers swap in to fake a trusted brand name.
LOOKALIKE_MAP = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
    }
)

URGENCY_PATTERNS = (
    r"act now",
    r"immediately",
    r"within \d+ ?(hours|hrs|days)",
    r"account (has been )?(suspended|locked|disabled|limited)",
    r"verify your (account|identity|information)",
    r"unusual (activity|sign[- ]?in|login)",
    r"final (notice|warning|reminder)",
    r"your (account|payment) (will|may) be (closed|cancell?ed|terminated)",
    r"failure to .* will result",
    r"offer expires",
    r"expires (today|tonight|soon|in \d+)",
    r"limited[- ]time (offer|only)",
    r"last chance",
    r"act before",
    r"(today|tonight) only",
    r"ends (today|tonight|soon)",
)

# Official-sounding words attackers register into domains ("secure-login.com").
# Matched as whole domain labels, never substrings, so "accountingfirm.com" is
# left alone.
DOMAIN_LURE_WORDS = frozenset(
    {
        "secure",
        "security",
        "account",
        "accounts",
        "login",
        "logon",
        "signin",
        "signon",
        "verify",
        "verification",
        "validate",
        "confirm",
        "update",
        "auth",
        "authentication",
        "recovery",
        "unlock",
        "webscr",
        "banking",
        "wallet",
    }
)

# "Log in / verify / confirm your account" phrasing. Scoped to identity/account,
# not "verify your email", so routine sign-up confirmations don't trip it.
CREDENTIAL_LURE_PATTERNS = (
    r"verify your (account|identity)",
    r"confirm your (account|identity|password|login|sign[- ]?in details)",
    r"validate your (account|identity)",
    r"update your (account|payment|billing|card) (details|information|info)",
    r"(log ?in|sign ?in) to (verify|confirm|restore|reactivate|unlock|secure) your",
    r"(reactivate|restore|unlock) your (account|access)",
)

SENSITIVE_PATTERNS = {
    r"\b(pin|password|passcode)\b": "your secret PIN or password",
    r"\bgift ?cards?\b": "gift cards",
    r"\bwire(d|s)? (transfer|the|money|funds|payment|\$|\d)": "a wire transfer",
    r"\b(western union|moneygram)\b": "a wire transfer",
    r"\b(bitcoin|btc|crypto(currency)?|usdt)\b": "cryptocurrency",
    r"\b(social security|ssn)\b": "your Social Security number",
    r"\b(routing|account) number\b": "your bank account number",
    r"\b(cvv|card verification)\b": "your card security code",
}

# Demands for secrecy that isolate the victim — a hallmark of wire-transfer and
# gift-card fraud. Imperative phrasing only, so "this email is confidential"
# footers are not flagged.
SECRECY_PATTERNS = (
    r"do(?: not|n'?t) (tell|discuss|share|mention|inform|talk to|reach out to) "
    r".{0,30}(anyone|anybody|others|else|colleagues|staff|family|hr|management)",
    r"keep (?:this|it) (?:between us|confidential|secret|quiet|to yourself|private)",
    r"without (?:telling|informing|alerting) (?:anyone|anybody|others|management|hr)",
    r"(?:must|should) (?:stay|remain|be kept) (?:strictly )?"
    r"(?:confidential|secret|between us)",
)

GENERIC_GREETINGS = (
    "dear customer",
    "dear user",
    "dear account holder",
    "dear member",
    "dear sir/madam",
    "dear valued customer",
)

# Cyrillic/Greek letters that look identical to Latin ones — used to fake a
# trusted brand (e.g. "аpple.com" with a Cyrillic "а").
CONFUSABLES = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "і": "i",
    "ѕ": "s",
    "ј": "j",
    "ο": "o",
    "α": "a",
    "ԁ": "d",
}

# Tech-support / "call us now" scams, which often carry no link at all.
TECH_SUPPORT_PATTERNS = (
    r"your (computer|device|pc) (is|has been) (infected|hacked|compromised)",
    r"(virus|malware|trojan) (detected|found)",
    r"(microsoft|apple|windows|norton|mcafee) (support|security|help ?desk)",
    r"call (us |our )?(toll[- ]?free|immediately|now|support)",
    r"contact (us|support) (at|on)",
    r"do not (turn off|restart|shut down) your (computer|device)",
)

LOTTERY_PATTERNS = (
    r"you('ve| have)? (just )?won",
    r"(lottery|jackpot|sweepstakes|raffle)",
    r"(lucky|grand) (winner|prize)",
    r"claim your (prize|reward|winnings|money|refund|cash|payment|funds)",
    r"(eligible|entitled|qualify|due) (for|to|a) .{0,30}refund",
    r"(unclaimed|pending|outstanding) refund",
    r"unclaimed (funds|money|inheritance)",
    r"(inheritance|next of kin|beneficiary)",
    r"(million|billion) (dollars|usd|pounds|euros)",
)

PHONE_RE = re.compile(r"(?:\+?\d[\d\s().-]{7,}\d)")
MONEY_RE = re.compile(r"[$£€]\s?\d{1,3}(?:,\d{3})+(?:\.\d+)?")

# Attachment/file extensions, grouped by how dangerous they are to open.
EXECUTABLE_EXTENSIONS = frozenset(
    {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".jar", ".lnk", ".iso", ".img", ".msi"}
)
# Archives can hide an executable but are also used legitimately, so they only
# escalate to high alongside a delivery lure (see ATTACHMENT_LURE_RE).
ARCHIVE_EXTENSIONS = frozenset({".zip", ".rar", ".7z"})
# Web-page and macro-enabled office attachments rarely have a legitimate reason
# to reach an individual.
DANGEROUS_DOC_EXTENSIONS = frozenset({".html", ".htm", ".docm", ".xlsm", ".pptm"})
RISKY_EXTENSIONS = ARCHIVE_EXTENSIONS | DANGEROUS_DOC_EXTENSIONS

# Finance/HR/delivery themes used to bait people into opening an attachment.
ATTACHMENT_LURE_RE = re.compile(
    r"\b(payroll|invoice|receipt|remittance|purchase order|payment|statement|"
    r"salary|payslip|bonus|refund|shipment|shipping|delivery|parcel|tracking|"
    r"voicemail|voice ?mail|fax|scanned? document)\b",
    re.IGNORECASE,
)
_FILENAME_RE = re.compile(r"[\w.-]+\.[A-Za-z0-9]{2,4}(?:\.[A-Za-z0-9]{2,4})?")

_URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+", re.IGNORECASE)


class _LinkExtractor(HTMLParser):
    """Collect (visible_text, href) pairs from anchor tags."""

    def __init__(self):
        super().__init__()
        self.links = []
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append(
                {"text": "".join(self._text).strip(), "href": self._href.strip()}
            )
            self._href = None


class _TextStripper(HTMLParser):
    """Flatten HTML into plain text for keyword scanning."""

    def __init__(self):
        super().__init__()
        self._chunks = []

    def handle_data(self, data):
        self._chunks.append(data)

    @property
    def text(self):
        return " ".join(self._chunks)


def extract_links(html, plain_text):
    """Return a list of link dicts from both the HTML and plain-text bodies."""

    links = []
    if html:
        parser = _LinkExtractor()
        parser.feed(html)
        links.extend(parser.links)

    seen_hrefs = {link["href"] for link in links}
    for match in _URL_RE.finditer(plain_text or ""):
        href = match.group(0).rstrip(".,);")
        if href not in seen_hrefs:
            links.append({"text": href, "href": href})
            seen_hrefs.add(href)

    return links


def strip_html(html):
    parser = _TextStripper()
    parser.feed(html or "")
    return parser.text


def _host(url):
    value = (url or "").strip()
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value, flags=re.IGNORECASE)
    value = value.split("/")[0].split("?")[0].split("#")[0]
    value = value.split("@")[-1].split(":")[0]
    return value.lower().strip(".")


def registered_domain(value):
    """Return the registrable domain (e.g. ``paypal.com``) for a URL or host."""

    host = _host(value)
    if not host or any(char.isspace() for char in host):
        return ""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    labels = host.split(".")
    if len(labels) < 2:
        return host
    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def _normalize_label(label):
    return label.lower().translate(LOOKALIKE_MAP)


def check_link_text_mismatch(links, **_):
    """Visible link text claims one domain but the link goes somewhere else."""

    findings = []
    for link in links:
        shown_domains = {
            registered_domain(match.group(0))
            for match in _URL_RE.finditer(link["text"])
        }
        # Also treat a bare "paypal.com" in the text (no scheme) as a claim.
        for token in re.findall(r"[a-z0-9.-]+\.[a-z]{2,}", link["text"].lower()):
            shown_domains.add(registered_domain("http://" + token))
        shown_domains.discard("")

        real = registered_domain(link["href"])
        if real and shown_domains and real not in shown_domains:
            findings.append(
                Finding(
                    code="link_text_mismatch",
                    severity=HIGH,
                    evidence={
                        "shown": sorted(shown_domains)[0],
                        "real": real,
                    },
                )
            )
    return findings


def check_lookalike_domains(links, **_):
    """Link domains that imitate a known brand via typos or subdomains."""

    findings = []
    for link in links:
        host = _host(link["href"])
        if not host:
            continue
        real = registered_domain(link["href"])
        normalized_host = _normalize_label(host)

        for brand, canonical in BRANDS.items():
            if real == canonical:
                continue
            if brand in normalized_host:
                findings.append(
                    Finding(
                        code="lookalike_domain",
                        severity=HIGH,
                        evidence={
                            "brand": brand,
                            "real": real or host,
                            "canonical": canonical,
                        },
                    )
                )
                break

        if host.startswith("xn--") or ".xn--" in host:
            findings.append(
                Finding(
                    code="punycode_domain",
                    severity=MEDIUM,
                    evidence={"host": host},
                )
            )
    return findings


def check_raw_ip_urls(links, **_):
    """Links that point at a bare IP address instead of a domain name."""

    findings = []
    for link in links:
        host = _host(link["href"])
        candidate = host.split(":")[0]
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        findings.append(
            Finding(
                code="raw_ip_url",
                severity=HIGH,
                evidence={"host": candidate},
            )
        )
    return findings


def check_url_shorteners(links, **_):
    findings = []
    for link in links:
        if registered_domain(link["href"]) in SHORTENERS:
            findings.append(
                Finding(
                    code="url_shortener",
                    severity=MEDIUM,
                    evidence={"host": _host(link["href"])},
                )
            )
    return findings


def check_sender_mismatch(headers, **_):
    """The display name impersonates a brand the sending domain doesn't own,
    or the Reply-To domain differs from the From domain."""

    findings = []
    from_name = (headers.get("from_name") or "").lower()
    from_domain = registered_domain("http://" + headers.get("from_domain", ""))

    for brand, canonical in BRANDS.items():
        if brand in from_name and from_domain and from_domain != canonical:
            findings.append(
                Finding(
                    code="sender_brand_mismatch",
                    severity=HIGH,
                    evidence={
                        "brand": brand,
                        "from_domain": from_domain,
                        "canonical": canonical,
                    },
                )
            )
            break

    reply_domain = registered_domain("http://" + headers.get("reply_to_domain", ""))
    if from_domain and reply_domain and reply_domain != from_domain:
        findings.append(
            Finding(
                code="reply_to_mismatch",
                severity=MEDIUM,
                evidence={"from_domain": from_domain, "reply_domain": reply_domain},
            )
        )
    return findings


def check_urgency(body_text, **_):
    text = (body_text or "").lower()
    for pattern in URGENCY_PATTERNS:
        match = re.search(pattern, text)
        if match:
            return [
                Finding(
                    code="urgency_pressure",
                    severity=MEDIUM,
                    evidence={"phrase": match.group(0)},
                )
            ]
    return []


def check_sensitive_requests(body_text, **_):
    text = (body_text or "").lower()
    findings = []
    for pattern, label in SENSITIVE_PATTERNS.items():
        if re.search(pattern, text):
            findings.append(
                Finding(
                    code="sensitive_request",
                    severity=HIGH,
                    evidence={"thing": label},
                )
            )
    return findings


def check_secrecy(body_text, **_):
    """'Don't tell anyone' style pressure that isolates the victim."""

    text = (body_text or "").lower()
    for pattern in SECRECY_PATTERNS:
        match = re.search(pattern, text)
        if match:
            return [
                Finding(
                    code="secrecy_pressure",
                    severity=MEDIUM,
                    evidence={"phrase": match.group(0)},
                )
            ]
    return []


def check_generic_greeting(body_text, **_):
    text = (body_text or "").lower()
    for greeting in GENERIC_GREETINGS:
        if greeting in text:
            return [
                Finding(
                    code="generic_greeting",
                    severity=LOW,
                    evidence={"greeting": greeting},
                )
            ]
    return []


def _ascii_skeleton(text):
    return "".join(CONFUSABLES.get(char, char) for char in text)


def check_homograph_domains(links, **_):
    """Link domains using non-Latin lookalike characters (e.g. Cyrillic 'а')."""

    findings = []
    for link in links:
        host = _host(link["href"])
        confusable = any(char in CONFUSABLES for char in host)
        non_ascii = any(ord(char) > 127 for char in host)
        if not (confusable or non_ascii):
            continue
        skeleton = _ascii_skeleton(host)
        evidence = {"host": host, "skeleton": skeleton}
        for brand, canonical in BRANDS.items():
            if brand in skeleton:
                evidence["canonical"] = canonical
                break
        findings.append(
            Finding(code="homograph_domain", severity=HIGH, evidence=evidence)
        )
    return findings


def check_tech_support(body_text, **_):
    """'Your computer is infected — call this number' style scams."""

    text = (body_text or "").lower()
    for pattern in TECH_SUPPORT_PATTERNS:
        match = re.search(pattern, text)
        if match:
            return [
                Finding(
                    code="tech_support_scam",
                    severity=HIGH,
                    evidence={"phrase": match.group(0)},
                )
            ]
    return []


def check_call_a_number(body_text, **_):
    """A phone number paired with pressure to call — common in voice scams."""

    text = body_text or ""
    lowered = text.lower()
    phone = PHONE_RE.search(text)
    wants_call = "call" in lowered or "phone" in lowered or "contact us" in lowered
    if phone and wants_call:
        number = re.sub(r"\s+", " ", phone.group(0)).strip()
        return [
            Finding(
                code="call_a_number",
                severity=MEDIUM,
                evidence={"number": number},
            )
        ]
    return []


def check_lottery_prize(body_text, **_):
    """Lottery, prize, sweepstakes, and inheritance bait."""

    text = (body_text or "").lower()
    for pattern in LOTTERY_PATTERNS:
        match = re.search(pattern, text)
        if match:
            return [
                Finding(
                    code="lottery_prize",
                    severity=HIGH,
                    evidence={"phrase": match.group(0)},
                )
            ]
    if MONEY_RE.search(body_text or ""):
        return [
            Finding(
                code="lottery_prize",
                severity=MEDIUM,
                evidence={"phrase": MONEY_RE.search(body_text).group(0)},
            )
        ]
    return []


def check_attachments(body_text, attachments=None, **_):
    """Attachments (real or mentioned) with dangerous file types."""

    findings = []
    names = list(attachments or [])
    names.extend(_FILENAME_RE.findall(body_text or ""))
    has_lure = bool(ATTACHMENT_LURE_RE.search(body_text or ""))

    seen = set()
    for name in names:
        name = name.strip().lower()
        if not name or name in seen:
            continue
        seen.add(name)

        parts = name.split(".")
        extensions = ["." + part for part in parts[1:]]
        if not extensions:
            continue
        final_ext = extensions[-1]
        is_double = len(extensions) >= 2 and any(
            ext in EXECUTABLE_EXTENSIONS or ext in RISKY_EXTENSIONS
            for ext in extensions[:-1]
        )

        high_risk = (
            final_ext in EXECUTABLE_EXTENSIONS
            or final_ext in DANGEROUS_DOC_EXTENSIONS
        )
        if high_risk or is_double:
            severity = HIGH
        elif final_ext in ARCHIVE_EXTENSIONS:
            # An archive plus a delivery lure is the classic malware email;
            # on its own it is only suspicious.
            severity = HIGH if has_lure else MEDIUM
        else:
            continue

        findings.append(
            Finding(
                code="risky_attachment",
                severity=severity,
                evidence={"name": name, "ext": final_ext},
            )
        )
    return findings


def _lure_labels(domain):
    """Lure words appearing as whole labels in a registrable domain, ignoring
    the public-suffix tail."""

    labels = domain.split(".")
    head = labels[:-1] if len(labels) > 1 else labels
    parts = set()
    for label in head:
        parts.update(label.split("-"))
    return parts & DOMAIN_LURE_WORDS


def check_deceptive_domain(links, **_):
    """A link whose own registered domain is built from official-sounding words
    (e.g. "verify-account.example") rather than a real brand or company name."""

    findings = []
    seen = set()
    for link in links:
        registered = registered_domain(link["href"])
        if not registered or registered in seen:
            continue
        # Real brands, shorteners, and raw IPs are handled by other detectors.
        if registered in set(BRANDS.values()) or registered in SHORTENERS:
            continue
        try:
            ipaddress.ip_address(_host(link["href"]))
            continue
        except ValueError:
            pass

        hits = _lure_labels(registered)
        sld = registered.split(".")[0]
        if len(hits) >= 2:
            severity = HIGH
        elif len(hits) == 1 and "-" in sld:
            severity = MEDIUM
        else:
            continue

        seen.add(registered)
        findings.append(
            Finding(
                code="deceptive_domain",
                severity=severity,
                evidence={"host": registered, "words": ", ".join(sorted(hits))},
            )
        )
    return findings


def check_credential_lure(links, body_text, **_):
    """Asks you to log in / verify / confirm your account through a link — the
    core of credential phishing. Only fires when the message contains a link."""

    if not links:
        return []
    text = (body_text or "").lower()
    for pattern in CREDENTIAL_LURE_PATTERNS:
        match = re.search(pattern, text)
        if match:
            return [
                Finding(
                    code="credential_lure",
                    severity=MEDIUM,
                    evidence={"phrase": match.group(0)},
                )
            ]
    return []


ALL_CHECKS = (
    check_link_text_mismatch,
    check_lookalike_domains,
    check_deceptive_domain,
    check_credential_lure,
    check_homograph_domains,
    check_raw_ip_urls,
    check_url_shorteners,
    check_sender_mismatch,
    check_urgency,
    check_sensitive_requests,
    check_secrecy,
    check_generic_greeting,
    check_tech_support,
    check_call_a_number,
    check_lottery_prize,
    check_attachments,
)
