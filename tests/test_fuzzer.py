import pytest
import respx
import httpx
from pynzor.modules.fuzzer import (
    fuzz_directory,
    fuzz_request,
    load_wordlist,
    expand_candidates,
    is_request_mode,
    FuzzResult,
    BaselineSignature,
    _is_directory_hit,
)
from pynzor.utils.http_client import Response


@pytest.mark.asyncio
async def test_fuzz_directory_finds_200_path():
    """Directory fuzzing reports only the path returning a 200."""
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
    """An empty wordlist scans nothing and finds nothing."""
    result = await fuzz_directory(
        "http://example.com", [], threads=2, use_baseline=False
    )
    assert result.scanned == 0
    assert result.found == []


@pytest.mark.asyncio
async def test_fuzz_directory_filters_spa_catchall():
    """A SPA catch-all baseline is detected and all matching paths are filtered."""
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
    """With use_baseline=False, catch-all responses are not detected or filtered."""
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
    """A genuine hit is reported even when a catch-all baseline is present."""
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
    """load_wordlist returns all entries from a wordlist file."""
    entries = load_wordlist(str(test_wordlist))
    assert "/admin" in entries
    assert "/login" in entries
    assert "/test" in entries


def test_load_wordlist_missing_file():
    """load_wordlist raises FileNotFoundError for a nonexistent path."""
    with pytest.raises(FileNotFoundError):
        load_wordlist("/nonexistent/path/wordlist.txt")


def test_expand_candidates_adds_extensions():
    """expand_candidates appends normalized extensions without duplicating existing ones."""
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
    """expand_candidates returns the bare words when no extensions are given."""
    assert expand_candidates(["a", "b"], None) == ["a", "b"]


@pytest.mark.asyncio
async def test_fuzz_directory_extensions_expand():
    """Directory fuzzing tries each extension and reports the matching variant."""
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
    """Recursive fuzzing descends into a discovered directory one level deep."""
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
    """Request fuzzing substitutes FUZZ into a POST body and matches the right word."""
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
    """filter_codes excludes responses with the filtered status code."""
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
    """filter_size excludes responses whose body length matches the filtered size."""
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
    """Request fuzzing substitutes FUZZ into the URL path and matches the right word."""
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
    """Request fuzzing treats a 3xx as terminal so a 301 can match -mc 301."""
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
    """Empty --data stays in directory mode; non-empty data switches to request mode."""
    # An empty --data must not flip directory fuzzing into request mode.
    assert is_request_mode("http://example.com", data="") is False
    assert is_request_mode("http://example.com", data="x=1") is True


@pytest.mark.asyncio
async def test_fuzz_directory_caps_candidates():
    """max_candidates bounds the number of requests issued per base URL."""
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


@pytest.mark.asyncio
async def test_fuzz_request_caps_candidates():
    """max_candidates bounds the number of requests issued in request mode."""
    with respx.mock:
        respx.route().mock(return_value=httpx.Response(404, text="no"))
        result = await fuzz_request(
            "http://example.com/FUZZ",
            [f"w{i}" for i in range(20)],
            threads=5,
            max_candidates=3,
        )
    assert result.scanned == 3


@pytest.mark.asyncio
async def test_fuzz_directory_recursion_respects_max_candidates():
    """Recursive fuzzing stays within max_candidates across descended bases."""
    with respx.mock:
        # admin is a directory hit, so recursion would descend into it; the
        # budget must still cap total requests across both levels.
        respx.get("http://example.com/admin").mock(
            return_value=httpx.Response(200, text="dir index")
        )
        respx.route().mock(return_value=httpx.Response(404, text="no"))
        result = await fuzz_directory(
            "http://example.com",
            ["admin", "login", "test", "data"],
            threads=5,
            use_baseline=False,
            recursive=True,
            depth=2,
            max_candidates=5,
        )
    assert result.scanned <= 5


@pytest.mark.asyncio
async def test_fuzz_directory_recursion_stays_in_scope():
    """A directory hit that redirects off-host is not descended into."""
    with respx.mock:
        # /admin redirects to an external host; the client follows it, so the
        # discovered URL is on evil.com. Recursion must not scan that host.
        respx.get("http://example.com/admin").mock(
            return_value=httpx.Response(302, headers={"Location": "http://evil.com/admin"})
        )
        respx.get("http://evil.com/admin").mock(
            return_value=httpx.Response(200, text="external dir")
        )
        respx.get("http://example.com/login").mock(
            return_value=httpx.Response(404, text="no")
        )
        # Tripwire: if recursion leaked off-host, this would be requested.
        evil_child = respx.get("http://evil.com/admin/login").mock(
            return_value=httpx.Response(200, text="leaked")
        )
        result = await fuzz_directory(
            "http://example.com",
            ["admin", "login"],
            threads=2,
            use_baseline=False,
            recursive=True,
            depth=1,
        )
    assert not evil_child.called
    assert all("evil.com/admin/" not in f.url for f in result.found)


def _resp(status: int, body: str) -> Response:
    """Build a minimal Response for BaselineSignature.matches tests."""
    return Response(url="http://x/y", status_code=status, headers={}, body=body, latency=0.0)


def test_baseline_out_of_tolerance_skips_hash(monkeypatch):
    """A body whose size is well outside tolerance is rejected without hashing."""
    import pynzor.modules.fuzzer as fz

    baseline = BaselineSignature(
        status_code=200, content_length=100_000, body_hash="unused", probe_path="p"
    )

    def _boom(_body):  # pragma: no cover - must not be called
        raise AssertionError("_hash_body should not run past the length gate")

    monkeypatch.setattr(fz, "_hash_body", _boom)
    # Diff of 100_000 bytes is far beyond the 3% tolerance -> fast-path reject.
    assert baseline.matches(_resp(200, "a" * 200_000)) is False


def test_baseline_large_body_length_drift_matches_without_hash_match():
    """A large within-tolerance body matches even when the hash differs."""
    baseline = BaselineSignature(
        status_code=200, content_length=100_000, body_hash="not-the-real-hash", probe_path="p"
    )
    # Diff of 1_000 bytes is within 3% tolerance; hash won't match, but the
    # >=5000 length-drift fallback treats it as the baseline.
    assert baseline.matches(_resp(200, "a" * 101_000)) is True


def test_baseline_short_body_length_gap_skips_hash(monkeypatch):
    """A short baseline rejects an obviously different-length body without hashing."""
    import pynzor.modules.fuzzer as fz

    baseline = BaselineSignature(
        status_code=200, content_length=50, body_hash="unused", probe_path="p"
    )

    def _boom(_body):  # pragma: no cover - must not be called
        raise AssertionError("_hash_body should not run past the length gate")

    monkeypatch.setattr(fz, "_hash_body", _boom)
    # 5_000 vs 50 bytes far exceeds the max(20, 3%) tolerance -> fast-path reject.
    assert baseline.matches(_resp(200, "a" * 5_000)) is False


def test_baseline_short_body_exact_hash_match():
    """A short baseline still matches on an exact normalized-body hash."""
    from pynzor.modules.fuzzer import _hash_body

    body = "<html>catch-all</html>"
    baseline = BaselineSignature(
        status_code=200,
        content_length=len(body),
        body_hash=_hash_body(body),
        probe_path="p",
    )
    assert baseline.matches(_resp(200, body)) is True
    assert baseline.matches(_resp(200, "totally different content here")) is False


def test_is_directory_hit_accepts_307_and_308():
    """307/308 redirects are treated as recursable directory hits."""
    for code in (307, 308):
        fr = FuzzResult(
            url="http://example.com/admin",
            status_code=code,
            discovered=True,
            content_length=0,
            redirect="/admin/",
        )
        assert _is_directory_hit(fr) is True


def test_is_request_mode_detects_fuzz_in_header_name():
    """A FUZZ keyword in a header name routes to request mode."""
    assert is_request_mode("http://example.com", headers={"X-FUZZ": "1"}) is True
    assert is_request_mode("http://example.com", headers={"X-Real": "v"}) is False


@pytest.mark.asyncio
async def test_fuzz_request_substitutes_header_name():
    """FUZZ in a header key is substituted before the request is sent."""
    seen_headers = {}

    def responder(request):
        seen_headers.update(request.headers)
        return httpx.Response(200, text="ok")

    with respx.mock:
        respx.get("http://example.com/").mock(side_effect=responder)
        result = await fuzz_request(
            "http://example.com/",
            ["X-Custom"],
            headers={"FUZZ": "probe"},
            threads=1,
            match_codes=[200],
        )
    assert result.scanned == 1
    assert seen_headers.get("x-custom") == "probe"


def test_load_wordlist_utf8_non_ascii(tmp_path):
    """A wordlist with non-ASCII UTF-8 bytes loads without a decode error."""
    p = tmp_path / "words.txt"
    p.write_text("café\nnaïve\n# comment\nadmin\n", encoding="utf-8")
    words = load_wordlist(str(p))
    assert "café" in words
    assert "naïve" in words
    assert "admin" in words
    assert all(not w.startswith("#") for w in words)
