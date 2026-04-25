import pytest
import dns.resolver
from unittest.mock import patch, MagicMock

from modules.subdomain import enumerate_subdomains


def _mock_a_answer(ips: list[str]):
    """Return an object that iterates like a dnspython Answer yielding rdata."""
    records = []
    for ip in ips:
        rec = MagicMock()
        rec.__str__ = lambda self, _ip=ip: _ip
        records.append(rec)
    answer = MagicMock()
    answer.__iter__ = lambda self: iter(records)
    return answer


def _make_resolve(mapping: dict[str, list[str]], wildcard_ips: list[str] | None = None):
    """Build a Resolver.resolve side effect.

    mapping: real-subdomain → list of IPs (exact match)
    wildcard_ips: if set, any other A query returns these IPs (simulates wildcard DNS)
    Queries for non-A record types raise NoAnswer.
    Unknown names with no wildcard raise NXDOMAIN.
    """

    def _resolve(name, record_type):
        if record_type != "A":
            raise dns.resolver.NoAnswer()
        if name in mapping:
            return _mock_a_answer(mapping[name])
        if wildcard_ips is not None:
            return _mock_a_answer(wildcard_ips)
        raise dns.resolver.NXDOMAIN()

    return _resolve


@pytest.mark.asyncio
async def test_subdomain_wildcard_detected_and_filters():
    wildcard_ips = ["203.0.113.42"]
    side_effect = _make_resolve({}, wildcard_ips=wildcard_ips)

    with patch.object(dns.resolver.Resolver, "resolve", side_effect=side_effect):
        result = await enumerate_subdomains(
            "https://example.com",
            ["api", "mail", "test"],
            threads=3,
            check_http=False,
        )

    assert result.wildcard_detected is True
    assert "203.0.113.42" in result.wildcard_ips
    assert result.subdomains == []
    assert result.wildcard_filtered == 3


@pytest.mark.asyncio
async def test_subdomain_real_subdomain_distinguished_from_wildcard():
    wildcard_ips = ["203.0.113.42"]
    real_ips = ["198.51.100.10"]
    side_effect = _make_resolve(
        {"api.example.com": real_ips}, wildcard_ips=wildcard_ips
    )

    with patch.object(dns.resolver.Resolver, "resolve", side_effect=side_effect):
        result = await enumerate_subdomains(
            "https://example.com",
            ["api", "mail", "test"],
            threads=3,
            check_http=False,
        )

    assert result.wildcard_detected is True
    names = [s.subdomain for s in result.subdomains]
    assert "api.example.com" in names
    assert "mail.example.com" not in names
    assert result.wildcard_filtered == 2


@pytest.mark.asyncio
async def test_subdomain_no_wildcard_normal_path():
    side_effect = _make_resolve(
        {"api.example.com": ["198.51.100.10"]}, wildcard_ips=None
    )

    with patch.object(dns.resolver.Resolver, "resolve", side_effect=side_effect):
        result = await enumerate_subdomains(
            "https://example.com",
            ["api", "missing"],
            threads=2,
            check_http=False,
        )

    assert result.wildcard_detected is False
    assert result.wildcard_ips == []
    names = [s.subdomain for s in result.subdomains]
    assert names == ["api.example.com"]
    assert result.wildcard_filtered == 0


@pytest.mark.asyncio
async def test_subdomain_include_wildcard_flag_retains_matches():
    wildcard_ips = ["203.0.113.42"]
    side_effect = _make_resolve({}, wildcard_ips=wildcard_ips)

    with patch.object(dns.resolver.Resolver, "resolve", side_effect=side_effect):
        result = await enumerate_subdomains(
            "https://example.com",
            ["api", "mail"],
            threads=2,
            check_http=False,
            include_wildcard=True,
        )

    assert result.wildcard_detected is True
    assert len(result.subdomains) == 2
    assert all(s.record_type == "WILDCARD" for s in result.subdomains)
    assert all(s.verified is False for s in result.subdomains)
