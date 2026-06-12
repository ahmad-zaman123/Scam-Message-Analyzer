"""Finding data structures shared across the detection pipeline."""

from dataclasses import dataclass, field

HIGH = "high"
MEDIUM = "medium"
LOW = "low"

SEVERITY_WEIGHTS = {
    HIGH: 3,
    MEDIUM: 2,
    LOW: 1,
}


@dataclass(frozen=True)
class Finding:
    """A single suspicious signal detected in a message.

    ``code`` identifies the detector, ``severity`` drives scoring, and
    ``evidence`` carries the concrete details used to fill in the
    plain-language explanation template.
    """

    code: str
    severity: str
    evidence: dict = field(default_factory=dict)

    @property
    def weight(self):
        return SEVERITY_WEIGHTS.get(self.severity, 0)
