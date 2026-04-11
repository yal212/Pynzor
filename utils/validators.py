import re
from urllib.parse import urlparse
from typing import Optional


def is_valid_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def is_valid_domain(domain: str) -> bool:
    domain_pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    return bool(domain_pattern.match(domain))


def is_valid_target(target: str) -> tuple[bool, Optional[str]]:
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
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url.rstrip("/")


def extract_domain(url_or_domain: str) -> str:
    normalized = normalize_url(url_or_domain)
    parsed = urlparse(normalized)
    return parsed.netloc


def extract_root_domain(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) < 2:
        return domain
    return ".".join(parts[-2:])


def build_url(base: str, path: str) -> str:
    base = normalize_url(base)
    if not path.startswith("/"):
        path = "/" + path
    return base + path
