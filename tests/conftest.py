import pytest
import asyncio
from pathlib import Path


@pytest.fixture
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def test_wordlist(tmp_path):
    wordlist = tmp_path / "test-wordlist.txt"
    wordlist.write_text("/admin\n/login\n/test\n")
    return wordlist


@pytest.fixture
def config():
    return {
        "http": {
            "timeout": 10,
            "max_retries": 3,
            "rate_limit": 0.1,
            "user_agent": "TestAgent/1.0",
            "follow_redirects": True,
            "verify_ssl": False,
            "max_redirects": 5,
        },
        "scanner": {
            "common_ports": [80, 443],
            "timeout": 3,
            "concurrent": 50,
        },
        "fuzzer": {
            "threads": 5,
            "status_codes": [200, 403],
            "extensions": [".php", ".html"],
            "wordlist": "wordlists/common-dirs.txt",
        },
    }
