import pytest
import respx
import httpx
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
        # Baseline probes also 404 on unmocked paths (respx default) → no
        # baseline detected → normal behavior.
        result = await fuzz_directory(
            "http://example.com",
            ["admin", "login", "test"],
            threads=3,
            use_baseline=False,
        )
    assert result.scanned == 3
    assert len(result.found) == 1
    assert "admin" in result.found[0].url


@pytest.mark.asyncio
async def test_fuzz_directory_empty_wordlist():
    result = await fuzz_directory(
        "http://example.com", [], threads=2, use_baseline=False
    )
    assert result.scanned == 0
    assert result.found == []


@pytest.mark.asyncio
async def test_fuzz_directory_filters_spa_catchall():
    # Every path (including random baseline probes) returns 200 + same body.
    spa_body = "<html><body>SPA index</body></html>"
    with respx.mock:
        respx.get(url__startswith="http://spa.example.com/").mock(
            return_value=httpx.Response(200, text=spa_body)
        )
        result = await fuzz_directory(
            "http://spa.example.com",
            ["admin", "login", "test", "api"],
            threads=4,
            use_baseline=True,
        )

    assert result.baseline_detected is True
    assert result.baseline_status == 200
    assert result.found == []
    assert result.baseline_filtered == 4


@pytest.mark.asyncio
async def test_fuzz_directory_no_baseline_flag_disables_filtering():
    spa_body = "<html><body>SPA index</body></html>"
    with respx.mock:
        respx.get(url__startswith="http://spa.example.com/").mock(
            return_value=httpx.Response(200, text=spa_body)
        )
        result = await fuzz_directory(
            "http://spa.example.com",
            ["admin", "login"],
            threads=2,
            use_baseline=False,
        )

    assert result.baseline_detected is False
    assert len(result.found) == 2
    assert result.baseline_filtered == 0


@pytest.mark.asyncio
async def test_fuzz_directory_distinguishes_real_match_from_baseline():
    spa_body = "<html><body>SPA index placeholder content</body></html>"
    admin_body = "<html><body>Internal admin dashboard — login required</body></html>"

    with respx.mock:
        respx.get("http://mixed.example.com/admin").mock(
            return_value=httpx.Response(200, text=admin_body)
        )
        # Catch-all for every other path (including baseline probes + other wordlist entries)
        respx.get(url__regex=r"http://mixed\.example\.com/(?!admin$).*").mock(
            return_value=httpx.Response(200, text=spa_body)
        )
        result = await fuzz_directory(
            "http://mixed.example.com",
            ["admin", "login", "test"],
            threads=3,
            use_baseline=True,
        )

    assert result.baseline_detected is True
    assert len(result.found) == 1
    assert "admin" in result.found[0].url
    assert result.baseline_filtered == 2


def test_load_wordlist(test_wordlist):
    entries = load_wordlist(str(test_wordlist))
    assert "/admin" in entries
    assert "/login" in entries
    assert "/test" in entries


def test_load_wordlist_missing_file():
    with pytest.raises(FileNotFoundError):
        load_wordlist("/nonexistent/path/wordlist.txt")
