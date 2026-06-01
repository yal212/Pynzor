import pytest
import respx
import httpx
from modules.fuzzer import (
    fuzz_directory,
    fuzz_request,
    load_wordlist,
    expand_candidates,
    is_request_mode,
    FuzzResult,
)


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


def test_expand_candidates_adds_extensions():
    candidates = expand_candidates(["admin", "index.php"], ["php", ".html"])
    # bare word always present; extensions normalized to dotted form
    assert candidates == [
        "admin",
        "admin.php",
        "admin.html",
        "index.php",  # already ends with .php → not duplicated
        "index.php.html",
    ]


def test_expand_candidates_no_extensions():
    assert expand_candidates(["a", "b"], None) == ["a", "b"]


@pytest.mark.asyncio
async def test_fuzz_directory_extensions_expand():
    with respx.mock:
        respx.get("http://example.com/admin").mock(
            return_value=httpx.Response(404, text="nope")
        )
        respx.get("http://example.com/admin.php").mock(
            return_value=httpx.Response(200, text="panel")
        )
        respx.get("http://example.com/admin.html").mock(
            return_value=httpx.Response(404, text="nope")
        )
        result = await fuzz_directory(
            "http://example.com",
            ["admin"],
            threads=3,
            use_baseline=False,
            extensions=["php", "html"],
        )
    assert result.scanned == 3
    assert len(result.found) == 1
    assert result.found[0].url.endswith("admin.php")


@pytest.mark.asyncio
async def test_fuzz_directory_recursion_descends_one_level():
    with respx.mock:
        respx.get("http://example.com/admin").mock(
            return_value=httpx.Response(200, text="dir index")
        )
        respx.get("http://example.com/login").mock(
            return_value=httpx.Response(404, text="nope")
        )
        respx.get("http://example.com/admin/admin").mock(
            return_value=httpx.Response(404, text="nope")
        )
        respx.get("http://example.com/admin/login").mock(
            return_value=httpx.Response(200, text="secret")
        )
        result = await fuzz_directory(
            "http://example.com",
            ["admin", "login"],
            threads=2,
            use_baseline=False,
            recursive=True,
            depth=1,
        )
    urls = {f.url for f in result.found}
    assert "http://example.com/admin" in urls
    assert "http://example.com/admin/login" in urls
    assert result.scanned == 4


@pytest.mark.asyncio
async def test_fuzz_request_post_body_substitution():
    def responder(request):
        body = request.content.decode()
        return httpx.Response(200, text="welcome") if "password=admin" in body else httpx.Response(401, text="denied")

    with respx.mock:
        respx.post("http://example.com/login").mock(side_effect=responder)
        result = await fuzz_request(
            "http://example.com/login",
            ["wrong", "admin", "nope"],
            method="POST",
            data="password=FUZZ",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            threads=3,
            match_codes=[200],
        )
    assert result.mode == "request"
    assert result.scanned == 3
    assert len(result.found) == 1
    assert result.found[0].word == "admin"
    assert result.found[0].status_code == 200


@pytest.mark.asyncio
async def test_fuzz_request_filter_codes():
    def responder(request):
        body = request.content.decode()
        return httpx.Response(200, text="x") if "v=ok" in body else httpx.Response(403, text="x")

    with respx.mock:
        respx.post("http://example.com/").mock(side_effect=responder)
        result = await fuzz_request(
            "http://example.com/",
            ["ok", "bad"],
            method="POST",
            data="v=FUZZ",
            threads=2,
            filter_codes=[403],
        )
    assert {f.word for f in result.found} == {"ok"}


@pytest.mark.asyncio
async def test_fuzz_request_filter_size():
    def responder(request):
        body = request.content.decode()
        return httpx.Response(200, text="MUCH LONGER BODY") if "id=2" in body else httpx.Response(200, text="small")

    with respx.mock:
        respx.post("http://example.com/").mock(side_effect=responder)
        result = await fuzz_request(
            "http://example.com/",
            ["1", "2", "3"],
            method="POST",
            data="id=FUZZ",
            threads=3,
            filter_size=len("small"),
        )
    assert len(result.found) == 1
    assert result.found[0].word == "2"


@pytest.mark.asyncio
async def test_fuzz_request_url_keyword_substitution():
    with respx.mock:
        respx.get("http://example.com/admin").mock(
            return_value=httpx.Response(200, text="ok")
        )
        respx.get("http://example.com/secret").mock(
            return_value=httpx.Response(404, text="no")
        )
        result = await fuzz_request(
            "http://example.com/FUZZ",
            ["admin", "secret"],
            match_codes=[200],
        )
    assert len(result.found) == 1
    assert result.found[0].word == "admin"


@pytest.mark.asyncio
async def test_fuzz_request_does_not_follow_redirects():
    # ffuf treats 3xx as terminal; the client must not resolve a 301 to its
    # 200 target, otherwise -mc 301 could never match.
    with respx.mock:
        respx.get("http://example.com/old").mock(
            return_value=httpx.Response(301, headers={"Location": "/new"})
        )
        respx.get("http://example.com/keep").mock(
            return_value=httpx.Response(404, text="no")
        )
        result = await fuzz_request(
            "http://example.com/FUZZ",
            ["old", "keep"],
            match_codes=[301],
        )
    assert len(result.found) == 1
    assert result.found[0].word == "old"
    assert result.found[0].status_code == 301


def test_is_request_mode_empty_data_stays_directory():
    # An empty --data must not flip directory fuzzing into request mode.
    assert is_request_mode("http://example.com", data="") is False
    assert is_request_mode("http://example.com", data="x=1") is True


@pytest.mark.asyncio
async def test_fuzz_directory_caps_candidates():
    # max_candidates must bound per-base fan-out, not just the BFS loop.
    with respx.mock:
        respx.route().mock(return_value=httpx.Response(404, text="no"))
        result = await fuzz_directory(
            "http://example.com",
            [f"w{i}" for i in range(20)],
            threads=5,
            use_baseline=False,
            max_candidates=3,
        )
    assert result.scanned == 3
