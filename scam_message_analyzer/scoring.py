"""Turn a list of findings into a single traffic-light verdict.

The logic is intentionally simple and explainable: any high-severity signal,
or enough smaller ones stacked together, makes the message red.
"""

from scam_message_analyzer.findings import HIGH

RED = "red"
YELLOW = "yellow"
GREEN = "green"

VERDICT_LABEL = {
    RED: "\U0001F534 LIKELY A SCAM",
    YELLOW: "\U0001F7E1 BE CAREFUL",
    GREEN: "\U0001F7E2 PROBABLY OKAY",
}

_RED_WEIGHT_THRESHOLD = 4


def score(findings):
    """Return ``(verdict, total_weight)`` for the given findings."""

    total = sum(finding.weight for finding in findings)
    has_high = any(finding.severity == HIGH for finding in findings)

    if not findings:
        return GREEN, 0
    if has_high or total >= _RED_WEIGHT_THRESHOLD:
        return RED, total
    return YELLOW, total
