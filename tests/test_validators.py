from pynzor.utils.validators import (
    extract_domain,
    extract_root_domain,
    is_valid_url,
    is_valid_domain,
    is_valid_target,
    normalize_url,
    build_url,
)


def test_extract_domain_strips_port():
    """A port suffix is stripped so the result is usable for DNS/connections."""
    assert extract_domain("https://example.com:8080/path") == "example.com"
    assert extract_domain("example.com:8080") == "example.com"


def test_extract_domain_bare_and_url():
    """Bare domains and plain URLs return the host unchanged."""
    assert extract_domain("example.com") == "example.com"
    assert extract_domain("https://sub.example.com/a/b") == "sub.example.com"
    assert extract_domain("http://example.com") == "example.com"


def test_is_valid_url():
    assert is_valid_url("https://example.com")
    assert is_valid_url("http://example.com/path?q=1")
    assert not is_valid_url("example.com")  # no scheme
    assert not is_valid_url("https://")  # no netloc
    assert not is_valid_url("not a url")


def test_is_valid_domain():
    assert is_valid_domain("example.com")
    assert is_valid_domain("sub.example.co.uk")
    assert not is_valid_domain("example")  # no TLD
    assert not is_valid_domain("-bad.com")  # leading hyphen
    assert not is_valid_domain("example.com/path")  # path is not a domain


def test_is_valid_target_urls():
    assert is_valid_target("https://example.com") == (True, None)
    ok, err = is_valid_target("http://[not-a-url")
    assert ok is False
    assert err == "Invalid URL format"


def test_is_valid_target_domains_and_errors():
    assert is_valid_target("example.com") == (True, None)
    assert is_valid_target("") == (False, "Target cannot be empty")
    assert is_valid_target("example.com/admin") == (False, "Invalid domain format")
    assert is_valid_target("notadomain") == (False, "Invalid target format")


def test_is_valid_target_strips_whitespace():
    assert is_valid_target("  example.com  ") == (True, None)


def test_normalize_url_adds_scheme_and_strips_slash():
    assert normalize_url("example.com") == "https://example.com"
    assert normalize_url("example.com/") == "https://example.com"
    assert normalize_url("http://example.com/") == "http://example.com"
    assert normalize_url("  example.com  ") == "https://example.com"


def test_normalize_url_is_idempotent():
    once = normalize_url("example.com/")
    assert normalize_url(once) == once


def test_extract_root_domain():
    assert extract_root_domain("a.b.example.com") == "example.com"
    assert extract_root_domain("example.com") == "example.com"
    assert extract_root_domain("localhost") == "localhost"  # fewer than two labels


def test_build_url_joins_and_normalizes():
    assert build_url("example.com", "admin") == "https://example.com/admin"
    assert build_url("example.com", "/admin") == "https://example.com/admin"
    assert build_url("http://example.com/", "/a/b") == "http://example.com/a/b"
