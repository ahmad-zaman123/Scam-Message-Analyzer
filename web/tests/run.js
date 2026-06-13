// Parity tests for the in-browser engine. Run: node tests/run.js
// Mirrors the Python unittest suite so the JS port stays trustworthy.

import assert from "node:assert/strict";
import { analyze } from "../src/analyzer.js";

let passed = 0;
const failures = [];
function test(name, fn) {
  try {
    fn();
    passed++;
  } catch (e) {
    failures.push(`${name}: ${e.message}`);
  }
}
const codes = (text) => new Set(analyze(text).findings.map((f) => f.code));
const verdict = (text) => analyze(text).verdict;

const CYR = "аррle.com"; // аррle.com (Cyrillic а, р, р)

// --- pipeline / scam vs legit ---
const SCAM_EMAIL = `From: PayPal Security <service@paypa1-secure.ru>
Reply-To: refunds@mail-helpdesk.net
Subject: Your account has been suspended

Dear Customer,

We noticed unusual activity on your account. Your account has been suspended.
You must verify your identity immediately or your account will be closed.

<a href="http://198.51.100.23/login">Log in to paypal.com</a>

Please confirm your password and card verification code to restore access.`;

test("scam email is red", () => assert.equal(verdict(SCAM_EMAIL), "red"));
test("detects link_text_mismatch", () => assert.ok(codes(SCAM_EMAIL).has("link_text_mismatch")));
test("detects raw_ip_url", () => assert.ok(codes(SCAM_EMAIL).has("raw_ip_url")));
test("detects sender_brand_mismatch", () => assert.ok(codes(SCAM_EMAIL).has("sender_brand_mismatch")));
test("detects reply_to_mismatch", () => assert.ok(codes(SCAM_EMAIL).has("reply_to_mismatch")));
test("detects urgency", () => assert.ok(codes(SCAM_EMAIL).has("urgency_pressure")));
test("detects sensitive_request", () => assert.ok(codes(SCAM_EMAIL).has("sensitive_request")));
test("detects generic_greeting", () => assert.ok(codes(SCAM_EMAIL).has("generic_greeting")));

const LEGIT = `From: Aunt Carol <carol@gmail.com>
Subject: Lunch on Sunday?

Hi Sam,

Are you free for lunch this Sunday around noon? Let me know.

Love,
Carol`;
test("legit email is green", () => {
  const r = analyze(LEGIT);
  assert.equal(r.verdict, "green");
  assert.equal(r.findings.length, 0);
});

// --- the five reported scenarios ---
test("bank phishing (lure domain) is red", () =>
  assert.equal(
    verdict(
      "URGENT: Your bank account has been suspended.\nVerify your identity immediately:\nhttp://secure-bank-login.verify-account.example\nFailure to verify within 24 hours will result in permanent account closure."
    ),
    "red"
  ));
test("cyrillic homograph email is red + flagged", () => {
  const msg = `From: support@${CYR}\nSubject: Apple Security Alert\n\nYour Apple ID has been locked.\n\nVisit:\nhttps://${CYR}/login\n\nThank you.`;
  assert.ok(codes(msg).has("homograph_domain"));
  assert.equal(verdict(msg), "red");
});
test("tax refund + shortener + expiry is red", () =>
  assert.equal(
    verdict("Subject: Tax Refund\n\nCongratulations!\n\nClaim your refund here:\nhttps://bit.ly/3ABCxyz\n\nOffer expires today."),
    "red"
  ));
test("wire transfer + secrecy is red", () => {
  const msg = "Subject: Confidential Payment\n\nPlease wire $18,750 today to the account below.\n\nDo not discuss this with anyone.";
  const c = codes(msg);
  assert.ok(c.has("sensitive_request") && c.has("secrecy_pressure"));
  assert.equal(verdict(msg), "red");
});
test("payroll archive (lure) is red", () =>
  assert.equal(verdict("Subject: Payroll\n\nAttached is your updated payroll.\n\nPayroll.zip"), "red"));

// --- false-positive guards ---
test("innocent zip stays yellow", () =>
  assert.equal(verdict("Hey, here are the holiday pictures I promised. vacation-photos.zip"), "yellow"));
test("legit brand subdomain not deceptive", () =>
  assert.ok(!codes("Sign in at https://accounts.google.com/signin to continue.").has("deceptive_domain")));
test("accountingfirm substring not deceptive", () =>
  assert.ok(!codes("Your invoice is at https://accountingfirm.com/portal").has("deceptive_domain")));
test("processed refund not lottery", () =>
  assert.ok(!codes("Your refund of $24.00 has been processed and posts in 3-5 days.").has("lottery_prize")));
test("wireless not wire transfer", () =>
  assert.ok(!codes("Your wireless bill is ready.").has("sensitive_request")));
test("plain apple.com not homograph", () =>
  assert.ok(!codes('<a href="http://apple.com/login">sign in</a>').has("homograph_domain")));

// --- extended detectors ---
test("tech support scam flagged", () =>
  assert.ok(codes("Warning: your computer is infected. Microsoft support detected a virus.").has("tech_support_scam")));
test("call a number flagged", () =>
  assert.ok(codes("Please call us immediately at 1-800-555-0199 to restore service.").has("call_a_number")));
test("phone without call context not flagged", () =>
  assert.ok(!codes("Our office is located at 123 Main Street, suite 4567890.").has("call_a_number")));
test("lottery win flagged", () =>
  assert.ok(codes("Congratulations! You have won the national lottery jackpot.").has("lottery_prize")));
test("executable double extension flagged", () =>
  assert.ok(codes("Open the attached invoice.pdf.exe now").has("risky_attachment")));
test("messages are non-empty", () =>
  assert.ok(analyze(SCAM_EMAIL).messages.every((m) => m && m.length)));

// --- report ---
if (failures.length) {
  console.error(`\n${failures.length} FAILED:`);
  for (const f of failures) console.error("  ✗ " + f);
  console.error(`\n${passed} passed, ${failures.length} failed`);
  process.exit(1);
} else {
  console.log(`\n✓ all ${passed} engine tests passed`);
}
