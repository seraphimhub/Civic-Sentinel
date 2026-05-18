from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True, slots=True)
class Target:
    raw: str
    scheme: str
    host: str
    port: int

    @property
    def normalized_url(self) -> str:
        default_port = 443 if self.scheme == "https" else 80
        port = "" if self.port == default_port else f":{self.port}"
        return f"{self.scheme}://{self.host}{port}"


def parse_target(value: str) -> Target:
    candidate = value.strip()
    if "://" not in candidate:
        candidate = f"https://{candidate}"

    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http and https targets are supported.")
    if not parsed.hostname:
        raise ValueError("Target must include a hostname.")

    default_port = 443 if parsed.scheme == "https" else 80
    return Target(raw=value, scheme=parsed.scheme, host=parsed.hostname.lower(), port=parsed.port or default_port)

