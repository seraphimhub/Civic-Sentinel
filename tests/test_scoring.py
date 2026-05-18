from civic_sentinel.models import Finding
from civic_sentinel.scoring import score_findings


def test_score_caps_at_100():
    findings = [
        Finding("a", "critical", "A", "e", "r"),
        Finding("b", "critical", "B", "e", "r"),
        Finding("c", "critical", "C", "e", "r"),
        Finding("d", "critical", "D", "e", "r"),
    ]
    assert score_findings(findings)["score"] == 100


def test_low_score_level():
    findings = [Finding("a", "low", "A", "e", "r")]
    risk = score_findings(findings)
    assert risk["score"] == 4
    assert risk["level"] == "low"

