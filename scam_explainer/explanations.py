"""Plain-language explanations for every finding code.

Wording is deliberately simple (around a 6th-grade reading level), calm,
and non-shaming. Each message states what was found and what to do, in
words a non-technical person can act on. These are hand-written and vetted
on purpose — there is no AI here to invent reasons.
"""

TEMPLATES = {
    "link_text_mismatch": (
        "A link in this message looks like it goes to \"{shown}\", but it "
        "really goes to \"{real}\". Real companies don't hide where a link "
        "leads. \U0001F449 Don't click it."
    ),
    "lookalike_domain": (
        "A link uses the web address \"{real}\", which is made to look like "
        "\"{canonical}\" ({brand}) but is not the same. This is a common trick. "
        "\U0001F449 Don't click it, and don't enter any details there."
    ),
    "punycode_domain": (
        "A link uses a disguised web address (\"{host}\") that can hide its "
        "real name using special characters. \U0001F449 Treat it as unsafe."
    ),
    "raw_ip_url": (
        "A link points to a plain number address ({host}) instead of a normal "
        "website name. Trustworthy companies almost never do this. "
        "\U0001F449 Don't click it."
    ),
    "url_shortener": (
        "A link uses a shortener ({host}) that hides where it really goes, so "
        "you can't tell the true destination. \U0001F449 Be very careful — "
        "don't click unless you fully trust the sender."
    ),
    "sender_brand_mismatch": (
        "This message says it is from {brand}, but it was actually sent from "
        "\"{from_domain}\", not their real address (\"{canonical}\"). "
        "\U0001F449 Treat it as fake."
    ),
    "reply_to_mismatch": (
        "If you reply, your answer would go to a different place "
        "(\"{reply_domain}\") than where this came from (\"{from_domain}\"). "
        "Scammers do this to catch your reply. \U0001F449 Don't reply."
    ),
    "urgency_pressure": (
        "This message tries to rush you (\"{phrase}\"). Scammers create panic "
        "so you act before you think. \U0001F449 Slow down — real problems can "
        "wait for you to check."
    ),
    "sensitive_request": (
        "This message is trying to get {thing}. A real company will not ask "
        "for this by email or text. \U0001F449 Never send it."
    ),
    "generic_greeting": (
        "The greeting is generic (\"{greeting}\") instead of your real name. "
        "Companies you have an account with usually know your name."
    ),
    "homograph_domain": (
        "A link's web address (\"{host}\") uses letters from another alphabet "
        "that look like normal English letters, to copy a real website. "
        "\U0001F449 Don't click it."
    ),
    "tech_support_scam": (
        "This message claims there is a problem with your computer or account "
        "(\"{phrase}\") to scare you into calling or acting. Real companies do "
        "not warn you this way. \U0001F449 Don't call any number in this message."
    ),
    "call_a_number": (
        "This message pushes you to call a phone number ({number}). Scammers "
        "use the phone to pressure you in the moment. \U0001F449 Don't call it "
        "— if it claims to be your bank, use the number on your card instead."
    ),
    "lottery_prize": (
        "This message says you have won or are owed money (\"{phrase}\"). If you "
        "didn't enter, you didn't win — this is a trick to get your details or "
        "a \"fee\". \U0001F449 Ignore it."
    ),
    "risky_attachment": (
        "There is a file named \"{name}\". This type of file ({ext}) can install "
        "harmful software on your device. \U0001F449 Don't open it."
    ),
}

GENERAL_ADVICE = (
    "When in doubt, do not click links or reply. Contact the company using a "
    "phone number or website you already know and trust — never the ones in "
    "this message."
)

GREEN_CAVEAT = (
    "Nothing obvious stood out, but scams can still slip through. If anything "
    "feels off, ask someone you trust before clicking or replying."
)


def explain(finding):
    template = TEMPLATES.get(finding.code)
    if template is None:
        return "Something about this message looks suspicious."
    return template.format(**finding.evidence)
