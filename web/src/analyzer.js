// Orchestrate parsing, detection, scoring, and explanation.
// Ported from scam_message_analyzer/analyzer.py. Email parsing is pragmatic
// (headers + body) rather than full MIME — enough for pasted text and emails.

import { ALL_CHECKS, extractLinks, stripHtml, registeredDomain } from "./checks.js";
import { explain } from "./explanations.js";
import { score } from "./scoring.js";

/** Mimic Python's email.utils.parseaddr for "Name <a@b>" or "a@b". */
function parseAddr(value) {
  const s = (value || "").trim();
  const m = s.match(/^(.*?)<([^>]*)>\s*$/);
  if (m) return [m[1].trim().replace(/^"|"$/g, ""), m[2].trim()];
  return ["", s];
}

function domainOf(value) {
  const [, addr] = parseAddr(value);
  return addr.includes("@") ? addr.split("@").pop().toLowerCase() : "";
}

function headerValue(raw, name) {
  const m = raw.match(new RegExp("^" + name + ":\\s*(.*)$", "im"));
  return m ? m[1] : "";
}

function parse(raw) {
  const headers = { from_name: "", from_domain: "", reply_to_domain: "" };
  let htmlBody = "";
  let plainBody = raw || "";
  const attachments = [];

  const looksLikeEmail = /^(from|subject|to|date):/im.test(raw || "");
  if (looksLikeEmail) {
    const [name, addr] = parseAddr(headerValue(raw, "From"));
    headers.from_name = name;
    headers.from_domain = addr.includes("@") ? addr.split("@").pop().toLowerCase() : "";
    headers.reply_to_domain = domainOf(headerValue(raw, "Reply-To"));

    const split = (raw || "").search(/\r?\n\r?\n/);
    plainBody = split >= 0 ? raw.slice(split).replace(/^\r?\n\r?\n/, "") : "";
  } else if (/<a\s/i.test(raw || "") || /<html/i.test(raw || "")) {
    htmlBody = raw;
    plainBody = "";
  }

  if (!htmlBody && /<a\s/i.test(plainBody || "")) htmlBody = plainBody;

  return { headers, htmlBody, plainBody, attachments };
}

/** Analyze a raw email or message and return a report object. */
export function analyze(raw) {
  const { headers, htmlBody, plainBody, attachments } = parse(raw);
  const links = extractLinks(htmlBody, plainBody);
  const bodyText = [stripHtml(htmlBody), plainBody].filter(Boolean).join(" ");

  const ctx = { links, headers, bodyText, attachments };
  let findings = [];
  for (const check of ALL_CHECKS) findings = findings.concat(check(ctx));

  findings.sort((a, b) => b.weight - a.weight);
  const [verdict, weight] = score(findings);
  const messages = findings.map(explain);
  return { verdict, weight, findings, messages };
}

export { registeredDomain };
