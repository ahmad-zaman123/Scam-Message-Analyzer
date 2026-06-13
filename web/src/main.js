// UI wiring for the browser app. Calls the same engine the CLI uses, entirely
// client-side — the message is never sent anywhere.

import { analyze } from "./analyzer.js";
import { GREEN, RED, YELLOW, VERDICT_LABEL } from "./scoring.js";
import { GENERAL_ADVICE, GREEN_CAVEAT } from "./explanations.js";

const DEFAULT_TITLE = "Is this a scam?";

const BANNER_COLORS = { [RED]: "#c0392b", [YELLOW]: "#b9770e", [GREEN]: "#1e8449" };
const PDF_TITLES = {
  [RED]: "Scam check - likely a scam",
  [YELLOW]: "Scam check - be careful",
  [GREEN]: "Scam check - probably okay",
};

const EXAMPLE_MESSAGE = [
  "Subject: Urgent: your account is suspended",
  "",
  "Dear Customer,",
  "",
  "We detected unusual activity on your account. Verify your identity",
  "immediately at http://secure-login.verify-account.example or your",
  "account will be permanently closed within 24 hours.",
].join("\n");

const messageEl = document.getElementById("message");
const resultEl = document.getElementById("result");

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text; // textContent => safe, no XSS
  return node;
}

function renderResult(report, message) {
  const frag = document.createDocumentFragment();

  // Echo of the checked message — hidden on screen, shown when printing/saving.
  const echo = el("section", "checked-message");
  echo.appendChild(el("h2", null, "Message you checked:"));
  echo.appendChild(el("pre", null, message));
  frag.appendChild(echo);

  const banner = el("div", "banner", VERDICT_LABEL[report.verdict]);
  banner.style.background = BANNER_COLORS[report.verdict] || "#444";
  frag.appendChild(banner);

  if (report.messages.length) {
    frag.appendChild(el("h2", null, "Here's what looks suspicious:"));
    const list = el("ul", "findings");
    list.style.setProperty("--accent", BANNER_COLORS[report.verdict] || "#444");
    for (const m of report.messages) list.appendChild(el("li", null, m));
    frag.appendChild(list);
  }

  frag.appendChild(
    el("p", "advice", report.verdict === GREEN ? GREEN_CAVEAT : GENERAL_ADVICE)
  );

  const pdfBtn = el("button", "btn btn-secondary printbtn", "Save as PDF");
  pdfBtn.type = "button";
  pdfBtn.addEventListener("click", () => {
    const prev = document.title;
    document.title = PDF_TITLES[report.verdict] || "Scam check";
    const restore = () => {
      document.title = prev;
      window.removeEventListener("afterprint", restore);
    };
    window.addEventListener("afterprint", restore);
    window.print();
  });
  frag.appendChild(pdfBtn);

  return frag;
}

function showNotice(text) {
  resultEl.replaceChildren(el("p", "notice", text));
}

function check(message) {
  const text = message != null ? message : messageEl.value;
  if (!text.trim()) {
    document.title = DEFAULT_TITLE;
    showNotice("Please paste a message above first.");
    return;
  }
  const report = analyze(text);
  resultEl.replaceChildren(renderResult(report, text));
  document.title = `${VERDICT_LABEL[report.verdict]} — ${DEFAULT_TITLE}`;
  resultEl.scrollIntoView({ behavior: "smooth", block: "start" });
}

function clearAll() {
  messageEl.value = "";
  resultEl.replaceChildren();
  document.title = DEFAULT_TITLE;
  messageEl.focus();
}

function loadExample() {
  messageEl.value = EXAMPLE_MESSAGE;
  check(EXAMPLE_MESSAGE);
}

function setupTheme() {
  const toggle = document.getElementById("themeToggle");
  const sync = () => {
    const dark = document.documentElement.getAttribute("data-theme") === "dark";
    toggle.textContent = dark ? "☀️" : "🌙";
    toggle.setAttribute("aria-pressed", String(dark));
  };
  sync();
  toggle.addEventListener("click", () => {
    const dark = document.documentElement.getAttribute("data-theme") === "dark";
    const next = dark ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try {
      localStorage.setItem("theme", next);
    } catch (e) {}
    sync();
  });
}

document.getElementById("checkBtn").addEventListener("click", () => check());
document.getElementById("exampleBtn").addEventListener("click", loadExample);
document.getElementById("clearBtn").addEventListener("click", clearAll);
setupTheme();
