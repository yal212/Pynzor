import pytest
import respx
import httpx
from pathlib import Path
from modules.fuzzer import fuzz_directory, load_wordlist, FuzzResult


@pytest.mark.asyncio
async def test_fuzz_directory_finds_200_path():
    with respx.mock:
        respx.get("http://example.com/admin").mock(
            return_value=httpx.Response(200, text="Admin panel")
        )
        respx.get("http://example.com/login").mock(
            return_value=httpx.Response(404, text="Not found")
        )
        respx.get("http://example.com/test").mock(
            return_value=httpx.Response(404, text="Not found")
        )
        result = await fuzz_directory("http://example.com", ["admin", "login", "test"], threads=3)
    assert result.scanned == 3
    assert len(result.found) == 1
    assert "admin" in result.found[0].url


@pytest.mark.asyncio
async def test_fuzz_directory_empty_wordlist():
    result = await fuzz_directory("http://example.com", [], threads=2)
    assert result.scanned == 0
    assert result.found == []


def test_load_wordlist(test_wordlist):
    entries = load_wordlist(str(test_wordlist))
    assert "/admin" in entries
    assert "/login" in entries
    assert "/test" in entries


def test_load_wordlist_missing_file():
    with pytest.raises(FileNotFoundError):
        load_wordlist("/nonexistent/path/wordlist.txt")
