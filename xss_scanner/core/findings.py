"""Finding dataclass and dedupe for reflected-XSS results."""

from __future__ import annotations

from dataclasses import dataclass

SEVERITY_ORDER = {"critical": 2, "medium": 1, "low": 0}


@dataclass
class Finding:
    title: str
    severity: str        # "critical" | "medium" | "low"
    verdict: str          # "confirmed" | "likely" | "info"
    request_url: str
    param_name: str
    param_location: str
    context_type: str
    payload_value: str
    evidence: str = ""

    def sort_key(self) -> tuple[int, str]:
        return (SEVERITY_ORDER.get(self.severity, 0) * -1, self.title)


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse findings for the same severity/context/param, keep the first."""
    seen: dict[tuple[str, str, str, str], Finding] = {}
    for finding in findings:
        key = (finding.severity, finding.context_type, finding.param_name, finding.param_location)
        if key not in seen:
            seen[key] = finding
    return sorted(seen.values(), key=lambda f: f.sort_key())
