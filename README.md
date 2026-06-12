# Scam Message Analyzer

![tests](https://github.com/ahmad-zaman123/Scam-Message-Analyzer/actions/workflows/ci.yml/badge.svg)

Paste a suspicious email and get a calm, plain-language explanation of **why**
it looks like a scam — written for a non-technical person (e.g. an elderly
relative). The goal is to teach instinct, not just block.

- **No AI, no API keys, no cost.** Every verdict comes from explainable rules.
- **Fully offline.** Nothing about the message ever leaves your machine.
- **Predictable.** The same email always gets the same answer — and you can
  read exactly why in `scam_message_analyzer/checks.py`.

## How it works

1. **Deterministic checks** (`checks.py`) scan the message for known scam
   signals:
   - Link text that hides its real destination, and lookalike domains
     (`paypa1.ru`)
   - **Homograph domains** — non-Latin lookalike letters (Cyrillic `аpple.com`)
   - Raw-IP links, punycode, and URL shorteners
   - Sender/brand mismatches and Reply-To redirection
   - Urgency pressure and requests for PINs / gift cards / wire transfers
   - **Tech-support scares** ("your computer is infected") and **"call this
     number"** pressure
   - **Lottery / prize / inheritance** bait and suspiciously large amounts
   - **Risky attachments** (`.exe`, `.scr`, double extensions like
     `invoice.pdf.exe`, `.html`, `.zip`)
2. **Scoring** (`scoring.py`) rolls the signals into one traffic light:
   🔴 likely a scam · 🟡 be careful · 🟢 probably okay.
3. **Explanations** (`explanations.py`) turn each signal into one short,
   hand-written sentence plus a clear next step.

## Usage

```bash
# Check a saved email
python -m scam_message_analyzer email.txt

# Check a screenshot of a text or email (see OCR note below)
python -m scam_message_analyzer screenshot.png

# Or pipe it in
cat email.txt | python -m scam_message_analyzer
```

Accepts a full raw email (with `From:` / `Subject:` headers), just pasted body
text, or an image. No `pip install` needed — it runs on the standard library.

### Web page (easiest for non-technical users)

The CLI is fine for developers, but the person this tool protects won't type
commands. Run a small **local** web page instead — a big paste box and one
button. A caregiver can bookmark it; the relative just pastes and clicks.

```bash
python -m scam_message_analyzer.web
# then open http://127.0.0.1:8765 in a browser
```

Still fully offline — it binds to localhost only and nothing is uploaded,
logged, or stored.

### Screenshots (OCR)

Most people who want a message checked have a *screenshot*, not its raw text.
Pass an image and the tool reads it with the local **Tesseract** OCR engine —
still fully offline, nothing uploaded. Tesseract is only needed for images;
text and `.eml` input work without it.

```bash
# Ubuntu/Debian
sudo apt install tesseract-ocr
# macOS
brew install tesseract
```

If it isn't installed, the tool tells you how to get it.

**QR codes ("quishing").** Many scams now hide the link inside a QR code that
OCR can't read. If the optional `zbarimg` tool is installed
(`sudo apt install zbar-tools`), the tool decodes QR codes in a screenshot and
runs the hidden link through the same checks. It's a bonus — everything else
works without it.

## Tests

```bash
python -m unittest discover -s tests
```

## Optional, later: nicer phrasing

If you ever want softer, more natural wording, you can add a **local** model
(via Ollama) that only *rephrases* the already-decided findings — the verdict
never depends on it. Still free, still offline. Not included here on purpose:
fixed, vetted wording is safer for the people this tool is for.

## Why not just use an LLM?

For safety tooling aimed at vulnerable users, predictable beats fluent. A
hand-written rule can't hallucinate a reason or wrongly reassure someone about
a real scam, and no personal email gets sent to a third party.
