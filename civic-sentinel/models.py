from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(slots=True)
class Finding:
    check_id: str
    severity: str
    title: str
    evidence: str
    recommendation: str

    def to_dict(self) -> dict:
        return asdict(self)


SEVERITY_WEIGHT = {
    "critical": 30,
    "high": 20,
    "medium": 10,
    "low": 4,
    "info": 0,
}

