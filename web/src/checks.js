// Deterministic detectors — pure, testable rules, no network, no AI.
// Ported from scam_message_analyzer/checks.py.

import { finding, HIGH, MEDIUM, LOW } from "./findings.js";

// Common two-part public suffixes, so "bbc.co.uk" -> "bbc.co.uk" not "co.uk".
const MULTI_SUFFIXES = new Set([
  "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "co.jp", "ne.jp", "or.jp",
  "com.au", "net.au", "org.au", "co.nz", "co.in", "co.za", "com.br", "com.mx",
  "com.sg", "com.hk",
]);

// Canonical domains for commonly-impersonated brands.
const BRANDS = {
  paypal: "paypal.com", apple: "apple.com", amazon: "amazon.com",
  microsoft: "microsoft.com", google: "google.com", netflix: "netflix.com",
  facebook: "facebook.com", instagram: "instagram.com", whatsapp: "whatsapp.com",
  fedex: "fedex.com", ups: "ups.com", usps: "usps.com", dhl: "dhl.com",
  irs: "irs.gov", chase: "chase.com", wellsfargo: "wellsfargo.com",
  bankofamerica: "bankofamerica.com", coinbase: "coinbase.com",
};
const BRAND_DOMAINS = new Set(Object.values(BRANDS));

// Common link-shortening services — they hide the true destination.
const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
  "rebrand.ly", "cutt.ly", "rb.gy",
]);

// Characters scammers swap in to fake a trusted brand name.
const LOOKALIKE_MAP = {
  "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s",
};

const URGENCY_PATTERNS = [
  /act now/, /immediately/, /within \d+ ?(hours|hrs|days)/,
  /account (has been )?(suspended|locked|disabled|limited)/,
  /verify your (account|identity|information)/,
  /unusual (activity|sign[- ]?in|login)/,
  /final (notice|warning|reminder)/,
  /your (account|payment) (will|may) be (closed|cancell?ed|terminated)/,
  /failure to .* will result/,
  /offer expires/, /expires (today|tonight|soon|in \d+)/,
  /limited[- ]time (offer|only)/, /last chance/, /act before/,
  /(today|tonight) only/, /ends (today|tonight|soon)/,
];

// Official-sounding words attackers register into domains ("secure-login.com").
const DOMAIN_LURE_WORDS = new Set([
  "secure", "security", "account", "accounts", "login", "logon", "signin",
  "signon", "verify", "verification", "validate", "confirm", "update", "auth",
  "authentication", "recovery", "unlock", "webscr", "banking", "wallet",
]);

// "Log in / verify / confirm your account" phrasing.
const CREDENTIAL_LURE_PATTERNS = [
  /verify your (account|identity)/,
  /confirm your (account|identity|password|login|sign[- ]?in details)/,
  /validate your (account|identity)/,
  /update your (account|payment|billing|card) (details|information|info)/,
  /(log ?in|sign ?in) to (verify|confirm|restore|reactivate|unlock|secure) your/,
  /(reactivate|restore|unlock) your (account|access)/,
];

const SENSITIVE_PATTERNS = [
  [/\b(pin|password|passcode)\b/, "your secret PIN or password"],
  [/\bgift ?cards?\b/, "gift cards"],
  [/\bwire(d|s)? (transfer|the|money|funds|payment|\$|\d)/, "a wire transfer"],
  [/\b(western union|moneygram)\b/, "a wire transfer"],
  [/\b(bitcoin|btc|crypto(currency)?|usdt)\b/, "cryptocurrency"],
  [/\b(social security|ssn)\b/, "your Social Security number"],
  [/\b(routing|account) number\b/, "your bank account number"],
  [/\b(cvv|card verification)\b/, "your card security code"],
];

// Demands for secrecy that isolate the victim.
const SECRECY_PATTERNS = [
  /do(?: not|n'?t) (tell|discuss|share|mention|inform|talk to|reach out to) .{0,30}(anyone|anybody|others|else|colleagues|staff|family|hr|management)/,
  /keep (?:this|it) (?:between us|confidential|secret|quiet|to yourself|private)/,
  /without (?:telling|informing|alerting) (?:anyone|anybody|others|management|hr)/,
  /(?:must|should) (?:stay|remain|be kept) (?:strictly )?(?:confidential|secret|between us)/,
];

const GENERIC_GREETINGS = [
  "dear customer", "dear user", "dear account holder", "dear member",
  "dear sir/madam", "dear valued customer",
];

// Cyrillic/Greek letters that look identical to Latin ones.
const CONFUSABLES = {
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
  "і": "i", "ѕ": "s", "ј": "j", "ο": "o", "α": "a", "ԁ": "d",
};

const TECH_SUPPORT_PATTERNS = [
  /your (computer|device|pc) (is|has been) (infected|hacked|compromised)/,
  /(virus|malware|trojan) (detected|found)/,
  /(microsoft|apple|windows|norton|mcafee) (support|security|help ?desk)/,
  /call (us |our )?(toll[- ]?free|immediately|now|support)/,
  /contact (us|support) (at|on)/,
  /do not (turn off|restart|shut down) your (computer|device)/,
];

const LOTTERY_PATTERNS = [
  /you('ve| have)? (just )?won/,
  /(lottery|jackpot|sweepstakes|raffle)/,
  /(lucky|grand) (winner|prize)/,
  /claim your (prize|reward|winnings|money|refund|cash|payment|funds)/,
  /(eligible|entitled|qualify|due) (for|to|a) .{0,30}refund/,
  /(unclaimed|pending|outstanding) refund/,
  /unclaimed (funds|money|inheritance)/,
  /(inheritance|next of kin|beneficiary)/,
  /(million|billion) (dollars|usd|pounds|euros)/,
];

const PHONE_RE = /\+?\d[\d\s().-]{7,}\d/;
const MONEY_RE = /[$£€]\s?\d{1,3}(?:,\d{3})+(?:\.\d+)?/;

const EXECUTABLE_EXTENSIONS = new Set([
  ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".jar", ".lnk", ".iso", ".img", ".msi",
]);
const ARCHIVE_EXTENSIONS = new Set([".zip", ".rar", ".7z"]);
const DANGEROUS_DOC_EXTENSIONS = new Set([".html", ".htm", ".docm", ".xlsm", ".pptm"]);
const RISKY_EXTENSIONS = new Set([...ARCHIVE_EXTENSIONS, ...DANGEROUS_DOC_EXTENSIONS]);

const ATTACHMENT_LURE_RE =
  /\b(payroll|invoice|receipt|remittance|purchase order|payment|statement|salary|payslip|bonus|refund|shipment|shipping|delivery|parcel|tracking|voicemail|voice ?mail|fax|scanned? document)\b/i;

const FILENAME_RE = /[\w.-]+\.[A-Za-z0-9]{2,4}(?:\.[A-Za-z0-9]{2,4})?/g;
const URL_RE = /https?:\/\/[^\s<>"'\)\]]+/gi;
const ANCHOR_RE = /<a\b[^>]*\bhref\s*=\s*["']?([^"'\s>]+)["']?[^>]*>([\s\S]*?)<\/a>/gi;

// --- helpers --------------------------------------------------------------

function isIp(host) {
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) return m.slice(1).every((o) => Number(o) <= 255);
  return host.includes(":"); // crude IPv6
}

function host(url) {
  let value = (url || "").trim();
  value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
  value = value.split("/")[0].split("?")[0].split("#")[0];
  value = value.split("@").pop().split(":")[0];
  return value.toLowerCase().replace(/^\.+|\.+$/g, "");
}

export function registeredDomain(value) {
  const h = host(value);
  if (!h || /\s/.test(h)) return "";
  if (isIp(h)) return h;
  const labels = h.split(".");
  if (labels.length < 2) return h;
  const lastTwo = labels.slice(-2).join(".");
  if (MULTI_SUFFIXES.has(lastTwo) && labels.length >= 3) return labels.slice(-3).join(".");
  return lastTwo;
}

function normalizeLabel(label) {
  return [...label.toLowerCase()].map((c) => LOOKALIKE_MAP[c] || c).join("");
}

function asciiSkeleton(text) {
  return [...text].map((c) => CONFUSABLES[c] || c).join("");
}

export function stripHtml(html) {
  return (html || "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
}

export function extractLinks(html, plainText) {
  const links = [];
  const seen = new Set();
  if (html) {
    let m;
    ANCHOR_RE.lastIndex = 0;
    while ((m = ANCHOR_RE.exec(html))) {
      const href = m[1].trim();
      links.push({ text: stripHtml(m[2]).trim(), href });
      seen.add(href);
    }
  }
  let m;
  URL_RE.lastIndex = 0;
  while ((m = URL_RE.exec(plainText || ""))) {
    const href = m[0].replace(/[.,);]+$/, "");
    if (!seen.has(href)) {
      links.push({ text: href, href });
      seen.add(href);
    }
  }
  return links;
}

function lureLabels(domain) {
  const labels = domain.split(".");
  const head = labels.length > 1 ? labels.slice(0, -1) : labels;
  const parts = new Set();
  for (const label of head) for (const p of label.split("-")) parts.add(p);
  return [...parts].filter((p) => DOMAIN_LURE_WORDS.has(p));
}

// --- detectors ------------------------------------------------------------

function checkLinkTextMismatch({ links }) {
  const out = [];
  for (const link of links) {
    const shown = new Set();
    let m;
    URL_RE.lastIndex = 0;
    while ((m = URL_RE.exec(link.text))) shown.add(registeredDomain(m[0]));
    for (const token of link.text.toLowerCase().match(/[a-z0-9.-]+\.[a-z]{2,}/g) || []) {
      shown.add(registeredDomain("http://" + token));
    }
    shown.delete("");
    const real = registeredDomain(link.href);
    if (real && shown.size && !shown.has(real)) {
      out.push(finding("link_text_mismatch", HIGH, { shown: [...shown].sort()[0], real }));
    }
  }
  return out;
}

function checkLookalikeDomains({ links }) {
  const out = [];
  for (const link of links) {
    const h = host(link.href);
    if (!h) continue;
    const real = registeredDomain(link.href);
    const normalized = normalizeLabel(h);
    for (const [brand, canonical] of Object.entries(BRANDS)) {
      if (real === canonical) continue;
      if (normalized.includes(brand)) {
        out.push(finding("lookalike_domain", HIGH, { brand, real: real || h, canonical }));
        break;
      }
    }
    if (h.startsWith("xn--") || h.includes(".xn--")) {
      out.push(finding("punycode_domain", MEDIUM, { host: h }));
    }
  }
  return out;
}

function checkDeceptiveDomain({ links }) {
  const out = [];
  const seen = new Set();
  for (const link of links) {
    const registered = registeredDomain(link.href);
    if (!registered || seen.has(registered)) continue;
    if (BRAND_DOMAINS.has(registered) || SHORTENERS.has(registered)) continue;
    if (isIp(host(link.href))) continue;
    const hits = lureLabels(registered);
    const sld = registered.split(".")[0];
    let severity;
    if (hits.length >= 2) severity = HIGH;
    else if (hits.length === 1 && sld.includes("-")) severity = MEDIUM;
    else continue;
    seen.add(registered);
    out.push(
      finding("deceptive_domain", severity, { host: registered, words: hits.slice().sort().join(", ") })
    );
  }
  return out;
}

function checkRawIpUrls({ links }) {
  const out = [];
  for (const link of links) {
    const candidate = host(link.href).split(":")[0];
    if (isIp(candidate) && /^\d/.test(candidate)) {
      out.push(finding("raw_ip_url", HIGH, { host: candidate }));
    }
  }
  return out;
}

function checkUrlShorteners({ links }) {
  const out = [];
  for (const link of links) {
    if (SHORTENERS.has(registeredDomain(link.href))) {
      out.push(finding("url_shortener", MEDIUM, { host: host(link.href) }));
    }
  }
  return out;
}

function checkSenderMismatch({ headers }) {
  const out = [];
  const fromName = (headers.from_name || "").toLowerCase();
  const fromDomain = registeredDomain("http://" + (headers.from_domain || ""));
  for (const [brand, canonical] of Object.entries(BRANDS)) {
    if (fromName.includes(brand) && fromDomain && fromDomain !== canonical) {
      out.push(finding("sender_brand_mismatch", HIGH, { brand, from_domain: fromDomain, canonical }));
      break;
    }
  }
  const replyDomain = registeredDomain("http://" + (headers.reply_to_domain || ""));
  if (fromDomain && replyDomain && replyDomain !== fromDomain) {
    out.push(finding("reply_to_mismatch", MEDIUM, { from_domain: fromDomain, reply_domain: replyDomain }));
  }
  return out;
}

function checkUrgency({ bodyText }) {
  const text = (bodyText || "").toLowerCase();
  for (const pattern of URGENCY_PATTERNS) {
    const m = text.match(pattern);
    if (m) return [finding("urgency_pressure", MEDIUM, { phrase: m[0] })];
  }
  return [];
}

function checkSensitiveRequests({ bodyText }) {
  const text = (bodyText || "").toLowerCase();
  const out = [];
  for (const [pattern, label] of SENSITIVE_PATTERNS) {
    if (pattern.test(text)) out.push(finding("sensitive_request", HIGH, { thing: label }));
  }
  return out;
}

function checkSecrecy({ bodyText }) {
  const text = (bodyText || "").toLowerCase();
  for (const pattern of SECRECY_PATTERNS) {
    const m = text.match(pattern);
    if (m) return [finding("secrecy_pressure", MEDIUM, { phrase: m[0] })];
  }
  return [];
}

function checkGenericGreeting({ bodyText }) {
  const text = (bodyText || "").toLowerCase();
  for (const greeting of GENERIC_GREETINGS) {
    if (text.includes(greeting)) return [finding("generic_greeting", LOW, { greeting })];
  }
  return [];
}

function checkHomographDomains({ links }) {
  const out = [];
  for (const link of links) {
    const h = host(link.href);
    const confusable = [...h].some((c) => CONFUSABLES[c]);
    const nonAscii = [...h].some((c) => c.charCodeAt(0) > 127);
    if (!confusable && !nonAscii) continue;
    const skeleton = asciiSkeleton(h);
    const evidence = { host: h, skeleton };
    for (const [brand, canonical] of Object.entries(BRANDS)) {
      if (skeleton.includes(brand)) {
        evidence.canonical = canonical;
        break;
      }
    }
    out.push(finding("homograph_domain", HIGH, evidence));
  }
  return out;
}

function checkTechSupport({ bodyText }) {
  const text = (bodyText || "").toLowerCase();
  for (const pattern of TECH_SUPPORT_PATTERNS) {
    const m = text.match(pattern);
    if (m) return [finding("tech_support_scam", HIGH, { phrase: m[0] })];
  }
  return [];
}

function checkCallANumber({ bodyText }) {
  const text = bodyText || "";
  const lowered = text.toLowerCase();
  const phone = text.match(PHONE_RE);
  const wantsCall =
    lowered.includes("call") || lowered.includes("phone") || lowered.includes("contact us");
  if (phone && wantsCall) {
    return [finding("call_a_number", MEDIUM, { number: phone[0].replace(/\s+/g, " ").trim() })];
  }
  return [];
}

function checkLotteryPrize({ bodyText }) {
  const text = (bodyText || "").toLowerCase();
  for (const pattern of LOTTERY_PATTERNS) {
    const m = text.match(pattern);
    if (m) return [finding("lottery_prize", HIGH, { phrase: m[0] })];
  }
  const money = (bodyText || "").match(MONEY_RE);
  if (money) return [finding("lottery_prize", MEDIUM, { phrase: money[0] })];
  return [];
}

function checkCredentialLure({ links, bodyText }) {
  if (!links.length) return [];
  const text = (bodyText || "").toLowerCase();
  for (const pattern of CREDENTIAL_LURE_PATTERNS) {
    const m = text.match(pattern);
    if (m) return [finding("credential_lure", MEDIUM, { phrase: m[0] })];
  }
  return [];
}

function checkAttachments({ bodyText, attachments }) {
  const out = [];
  const names = [...(attachments || [])];
  for (const m of (bodyText || "").match(FILENAME_RE) || []) names.push(m);
  const hasLure = ATTACHMENT_LURE_RE.test(bodyText || "");

  const seen = new Set();
  for (let name of names) {
    name = name.trim().toLowerCase();
    if (!name || seen.has(name)) continue;
    seen.add(name);

    const parts = name.split(".");
    const extensions = parts.slice(1).map((p) => "." + p);
    if (!extensions.length) continue;
    const finalExt = extensions[extensions.length - 1];
    const isDouble =
      extensions.length >= 2 &&
      extensions.slice(0, -1).some((e) => EXECUTABLE_EXTENSIONS.has(e) || RISKY_EXTENSIONS.has(e));

    let severity;
    if (EXECUTABLE_EXTENSIONS.has(finalExt) || DANGEROUS_DOC_EXTENSIONS.has(finalExt) || isDouble) {
      severity = HIGH;
    } else if (ARCHIVE_EXTENSIONS.has(finalExt)) {
      severity = hasLure ? HIGH : MEDIUM;
    } else {
      continue;
    }
    out.push(finding("risky_attachment", severity, { name, ext: finalExt }));
  }
  return out;
}

export const ALL_CHECKS = [
  checkLinkTextMismatch,
  checkLookalikeDomains,
  checkDeceptiveDomain,
  checkCredentialLure,
  checkHomographDomains,
  checkRawIpUrls,
  checkUrlShorteners,
  checkSenderMismatch,
  checkUrgency,
  checkSensitiveRequests,
  checkSecrecy,
  checkGenericGreeting,
  checkTechSupport,
  checkCallANumber,
  checkLotteryPrize,
  checkAttachments,
];
