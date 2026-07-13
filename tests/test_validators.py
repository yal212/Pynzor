from pynzor.utils.validators import extract_domain


def test_extract_domain_strips_port():
    """A port suffix is stripped so the result is usable for DNS/connections."""
    assert extract_domain("https://example.com:8080/path") == "example.com"
    assert extract_domain("example.com:8080") == "example.com"


def test_extract_domain_bare_and_url():
    """Bare domains and plain URLs return the host unchanged."""
    assert extract_domain("example.com") == "example.com"
    assert extract_domain("https://sub.example.com/a/b") == "sub.example.com"
    assert extract_domain("http://example.com") == "example.com"
