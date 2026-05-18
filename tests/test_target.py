import pytest

from civic_sentinel.target import parse_target


def test_parse_domain_defaults_to_https():
    target = parse_target("example.go.id")
    assert target.scheme == "https"
    assert target.host == "example.go.id"
    assert target.port == 443
    assert target.normalized_url == "https://example.go.id"


def test_parse_url_with_port():
    target = parse_target("http://example.test:8080")
    assert target.scheme == "http"
    assert target.port == 8080
    assert target.normalized_url == "http://example.test:8080"


def test_rejects_unsupported_scheme():
    with pytest.raises(ValueError):
        parse_target("ftp://example.test")

