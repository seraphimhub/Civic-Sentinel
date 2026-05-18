from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from http.cookies import SimpleCookie

from .models import Finding
from .network import HttpResponse, fetch_tls_certificate, request, resolve_records
from .target import Target


SECURITY_HEADERS = {
    "strict-transport-security": (
        "high",
        "HSTS is missing",
        "Enable Strict-Transport-Security with a long max-age after validating HTTPS across subdomains.",
    ),
    "content-security-policy": (
        "medium",
        "Content-Security-Policy is missing",
        "Add a restrictive CSP to reduce XSS and injection impact.",
    ),
    "x-frame-options": (
        "medium",
        "Clickjacking protection header is missing",
        "Set X-Frame-Options or use CSP frame-ancestors.",
    ),
    "x-content-type-options": (
        "low",
        "MIME sniffing protection is missing",
        "Set X-Content-Type-Options: nosniff.",
    ),
    "referrer-policy": (
        "low",
        "Referrer-Policy is missing",
        "Set a privacy-preserving Referrer-Policy such as strict-origin-when-cross-origin.",
    ),
    "permissions-policy": (
        "low",
        "Permissions-Policy is missing",
        "Restrict browser features that the site does not need.",
    ),
}


def check_dns(target: Target) -> tuple[dict, list[Finding]]:
    details = {
        "A": resolve_records(target.host, "A"),
        "AAAA": resolve_records(target.host, "AAAA"),
    }
    findings: list[Finding] = []
    if not details["A"] and not details["AAAA"]:
        findings.append(
            Finding(
                "dns.no_address",
                "critical",
                "No public address record resolved",
                "No A or AAAA records were returned by the local resolver.",
                "Verify DNS delegation and authoritative records.",
            )
        )
    elif not details["AAAA"]:
        findings.append(
            Finding(
                "dns.no_ipv6",
                "info",
                "No IPv6 address record found",
                "The target resolved A records but no AAAA records.",
                "Add IPv6 only if the hosting and security monitoring stack can support it.",
            )
        )
    return details, findings


def check_tls(target: Target, timeout: float) -> tuple[dict, list[Finding]]:
    if target.scheme != "https":
        return {}, [
            Finding(
                "tls.not_https",
                "high",
                "Target is not using HTTPS",
                f"The target scheme is {target.scheme}.",
                "Serve the site over HTTPS and redirect HTTP to HTTPS.",
            )
        ]

    findings: list[Finding] = []
    try:
        tls = fetch_tls_certificate(target, timeout=timeout)
    except Exception as exc:
        return {"error": str(exc)}, [
            Finding(
                "tls.handshake_failed",
                "high",
                "TLS handshake failed",
                str(exc),
                "Inspect certificate chain, SNI configuration, and supported TLS versions.",
            )
        ]

    cert = tls.get("cert", {})
    not_after = cert.get("notAfter")
    if not_after:
        expires = parsedate_to_datetime(not_after)
        days_left = (expires - datetime.now(timezone.utc)).days
        tls["expires_at"] = expires.isoformat()
        tls["days_left"] = days_left
        if days_left < 0:
            findings.append(
                Finding(
                    "tls.expired",
                    "critical",
                    "TLS certificate is expired",
                    f"Certificate expired {abs(days_left)} days ago.",
                    "Renew the certificate immediately and verify automated renewal.",
                )
            )
        elif days_left <= 14:
            findings.append(
                Finding(
                    "tls.expiring",
                    "high",
                    "TLS certificate expires soon",
                    f"Certificate expires in {days_left} days.",
                    "Renew the certificate and verify monitoring for certificate expiry.",
                )
            )
        elif days_left <= 30:
            findings.append(
                Finding(
                    "tls.expiring_soon",
                    "medium",
                    "TLS certificate is nearing expiry",
                    f"Certificate expires in {days_left} days.",
                    "Schedule renewal before the certificate enters the critical window.",
                )
            )

    version = tls.get("tls_version")
    if version in {"TLSv1", "TLSv1.1"}:
        findings.append(
            Finding(
                "tls.legacy_version",
                "high",
                "Legacy TLS version negotiated",
                f"Negotiated {version}.",
                "Disable TLS 1.0 and 1.1; prefer TLS 1.2 and TLS 1.3.",
            )
        )

    return tls, findings


def check_headers(response: HttpResponse, target: Target) -> list[Finding]:
    findings: list[Finding] = []
    for header, (severity, title, recommendation) in SECURITY_HEADERS.items():
        if header == "strict-transport-security" and target.scheme != "https":
            continue
        if header not in response.headers:
            findings.append(
                Finding(
                    f"headers.missing.{header}",
                    severity,
                    title,
                    f"{header} was not present in the root response.",
                    recommendation,
                )
            )

    server = ", ".join(response.headers.get("server", []))
    if server and any(token in server.lower() for token in ["/", "apache", "nginx", "iis", "php"]):
        findings.append(
            Finding(
                "headers.server_disclosure",
                "low",
                "Server technology is disclosed",
                f"Server header: {server}",
                "Reduce version disclosure where operationally practical.",
            )
        )
    return findings


def check_cookies(response: HttpResponse) -> list[Finding]:
    findings: list[Finding] = []
    for raw_cookie in response.headers.get("set-cookie", []):
        cookie = SimpleCookie()
        cookie.load(raw_cookie)
        lower_cookie = raw_cookie.lower()
        for name in cookie.keys():
            if "secure" not in lower_cookie:
                findings.append(
                    Finding(
                        "cookies.missing_secure",
                        "medium",
                        "Cookie missing Secure flag",
                        f"Cookie {name} did not include Secure.",
                        "Set Secure on session and sensitive cookies.",
                    )
                )
            if "httponly" not in lower_cookie:
                findings.append(
                    Finding(
                        "cookies.missing_httponly",
                        "medium",
                        "Cookie missing HttpOnly flag",
                        f"Cookie {name} did not include HttpOnly.",
                        "Set HttpOnly on cookies that do not need JavaScript access.",
                    )
                )
            if "samesite" not in lower_cookie:
                findings.append(
                    Finding(
                        "cookies.missing_samesite",
                        "low",
                        "Cookie missing SameSite attribute",
                        f"Cookie {name} did not include SameSite.",
                        "Set SameSite=Lax or Strict where compatible with the application flow.",
                    )
                )
    return findings


def check_methods(target: Target, timeout: float) -> tuple[dict, list[Finding]]:
    try:
        response = request(target, method="OPTIONS", path="/", timeout=timeout)
    except Exception as exc:
        return {"error": str(exc)}, [
            Finding(
                "http.options_failed",
                "info",
                "OPTIONS check could not complete",
                str(exc),
                "Manually confirm allowed methods if needed.",
            )
        ]

    allow = ", ".join(response.headers.get("allow", []))
    details = {"status": response.status, "allow": allow}
    risky = [method for method in ["PUT", "DELETE", "TRACE", "CONNECT"] if method in allow.upper()]
    findings = []
    if risky:
        findings.append(
            Finding(
                "http.risky_methods",
                "high",
                "Risky HTTP methods are advertised",
                f"Allow header includes: {', '.join(risky)}.",
                "Disable methods that are not required by the application.",
            )
        )
    return details, findings


def check_policy_files(target: Target, timeout: float) -> tuple[dict, list[Finding]]:
    paths = {
        "security_txt": "/.well-known/security.txt",
        "robots_txt": "/robots.txt",
    }
    details = {}
    findings: list[Finding] = []
    for key, path in paths.items():
        try:
            response = request(target, method="GET", path=path, timeout=timeout)
            details[key] = {"status": response.status, "bytes": len(response.body)}
        except Exception as exc:
            details[key] = {"error": str(exc)}

    security_status = details.get("security_txt", {}).get("status")
    if security_status != 200:
        findings.append(
            Finding(
                "policy.security_txt_missing",
                "low",
                "security.txt is not published",
                f"/.well-known/security.txt returned {security_status}.",
                "Publish security.txt with vulnerability disclosure contacts and policy.",
            )
        )
    return details, findings

