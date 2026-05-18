from __future__ import annotations

from datetime import datetime, timezone

from .checks import check_cookies, check_dns, check_headers, check_methods, check_policy_files, check_tls
from .models import Finding
from .network import request
from .scoring import score_findings
from .target import parse_target


def _finding_key(finding: Finding) -> tuple[int, str]:
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return rank.get(finding.severity, 5), finding.title


def scan_target(raw_target: str, timeout: float = 8.0) -> dict:
    target = parse_target(raw_target)
    findings: list[Finding] = []
    evidence: dict = {}

    dns_details, dns_findings = check_dns(target)
    evidence["dns"] = dns_details
    findings.extend(dns_findings)

    tls_details, tls_findings = check_tls(target, timeout=timeout)
    evidence["tls"] = tls_details
    findings.extend(tls_findings)

    try:
        root = request(target, method="GET", path="/", timeout=timeout)
        evidence["root_response"] = {
            "status": root.status,
            "reason": root.reason,
            "headers": root.headers,
            "body_sample_bytes": min(len(root.body), 512),
        }
        findings.extend(check_headers(root, target))
        findings.extend(check_cookies(root))
    except Exception as exc:
        evidence["root_response"] = {"error": str(exc)}
        findings.append(
            Finding(
                "http.root_unreachable",
                "high",
                "Root page could not be fetched",
                str(exc),
                "Check availability, firewall rules, DNS, and TLS configuration.",
            )
        )

    method_details, method_findings = check_methods(target, timeout=timeout)
    evidence["methods"] = method_details
    findings.extend(method_findings)

    policy_details, policy_findings = check_policy_files(target, timeout=timeout)
    evidence["policy_files"] = policy_details
    findings.extend(policy_findings)

    findings = sorted(findings, key=_finding_key)
    risk = score_findings(findings)
    return {
        "tool": {"name": "Civic Sentinel", "version": "0.1.0"},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": {
            "raw": raw_target,
            "normalized_url": target.normalized_url,
            "host": target.host,
            "port": target.port,
            "scheme": target.scheme,
        },
        "risk": risk,
        "findings": [finding.to_dict() for finding in findings],
        "evidence": evidence,
    }

