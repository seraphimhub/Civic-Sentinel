from __future__ import annotations

from .models import SEVERITY_WEIGHT, Finding


def score_findings(findings: list[Finding]) -> dict:
    raw = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in findings)
    score = min(100, raw)
    if score >= 75:
        level = "critical"
    elif score >= 50:
        level = "high"
    elif score >= 25:
        level = "medium"
    else:
        level = "low"
    return {"score": score, "level": level}

