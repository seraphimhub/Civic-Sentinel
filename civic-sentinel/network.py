from __future__ import annotations

import http.client
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urljoin

from .target import Target


USER_AGENT = "CivicSentinel/0.1 defensive-authorized-scanner"


@dataclass(slots=True)
class HttpResponse:
    status: int
    reason: str
    headers: dict[str, list[str]]
    body: bytes


def _connection(target: Target, timeout: float) -> http.client.HTTPConnection:
    if target.scheme == "https":
        return http.client.HTTPSConnection(target.host, target.port, timeout=timeout)
    return http.client.HTTPConnection(target.host, target.port, timeout=timeout)


def request(target: Target, method: str = "GET", path: str = "/", timeout: float = 8.0) -> HttpResponse:
    conn = _connection(target, timeout)
    try:
        conn.request(method, path, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
        response = conn.getresponse()
        body = response.read(128_000)
        headers: dict[str, list[str]] = {}
        for key, value in response.getheaders():
            headers.setdefault(key.lower(), []).append(value)
        return HttpResponse(status=response.status, reason=response.reason, headers=headers, body=body)
    finally:
        conn.close()


def resolve_records(host: str, record_type: str) -> list[str]:
    if record_type == "A":
        family = socket.AF_INET
    elif record_type == "AAAA":
        family = socket.AF_INET6
    else:
        return []

    records = set()
    try:
        for result in socket.getaddrinfo(host, None, family, socket.SOCK_STREAM):
            records.add(result[4][0])
    except socket.gaierror:
        return []
    return sorted(records)


def fetch_tls_certificate(target: Target, timeout: float = 8.0) -> dict:
    if target.scheme != "https":
        return {}

    context = ssl.create_default_context()
    with socket.create_connection((target.host, target.port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=target.host) as wrapped:
            cert = wrapped.getpeercert()
            return {
                "cipher": wrapped.cipher(),
                "tls_version": wrapped.version(),
                "cert": cert,
            }


def absolute_url(target: Target, path: str) -> str:
    return urljoin(target.normalized_url, path)

