import re
from urllib.parse import urlparse
from typing import Optional


def is_valid_url(url: str) -> bool:
    """Check whether a string is a well-formed URL.

    Args:
        url: Candidate URL string.

    Returns:
        True if the string parses with both a scheme and a network location.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def is_valid_domain(domain: str) -> bool:
    """Check whether a string is a syntactically valid domain name.

    Args:
        domain: Candidate domain (e.g. "example.com").

    Returns:
        True if the string matches a standard hostname pattern.
    """
    domain_pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    return bool(domain_pattern.match(domain))


def is_valid_target(target: str) -> tuple[bool, Optional[str]]:
    """Validate a scan target, which may be a URL or a bare domain.

    Args:
        target: User-supplied target string (URL or domain).

    Returns:
        A ``(is_valid, error_message)`` tuple. ``error_message`` is None when
        the target is valid, otherwise a human-readable reason.
    """
    if not target:
        return False, "Target cannot be empty"

    target = target.strip()

    if target.startswith(("http://", "https://")):
        if is_valid_url(target):
            return True, None
        return False, "Invalid URL format"

    if "/" in target:
        return False, "Invalid domain format"

    if is_valid_domain(target):
        return True, None

    return False, "Invalid target format"


def normalize_url(url: str) -> str:
    """Normalize a URL or domain into a canonical URL.

    Prepends ``https://`` when no scheme is present and strips any trailing
    slash.

    Args:
        url: URL or bare domain string.

    Returns:
        A normalized URL with a scheme and no trailing slash.
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url.rstrip("/")


def extract_domain(url_or_domain: str) -> str:
    """Extract the network location (host[:port]) from a URL or domain.

    Args:
        url_or_domain: URL or bare domain string.

    Returns:
        The netloc portion, e.g. "example.com" or "example.com:8080".
    """
    normalized = normalize_url(url_or_domain)
    parsed = urlparse(normalized)
    return parsed.netloc


def extract_root_domain(domain: str) -> str:
    """Reduce a domain to its registrable root (last two labels).

    Args:
        domain: Domain name, possibly with subdomains.

    Returns:
        The last two dot-separated labels (e.g. "a.b.example.com" ->
        "example.com"); returns the input unchanged if it has fewer than two
        labels.
    """
    parts = domain.split(".")
    if len(parts) < 2:
        return domain
    return ".".join(parts[-2:])


def build_url(base: str, path: str) -> str:
    """Join a base URL/domain and a path into a normalized absolute URL.

    Args:
        base: Base URL or domain.
        path: Path to append; a leading slash is added if missing.

    Returns:
        The combined URL.
    """
    base = normalize_url(base)
    if not path.startswith("/"):
        path = "/" + path
    return base + path
