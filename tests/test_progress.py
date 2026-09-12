"""Progress-callback contract for every module.

Two properties matter to a live frontend and are asserted for each module:
the event stream is monotonic and terminates at ``done == total``, and
supplying a callback does not change the result the module returns.
"""

import pytest

import pynzor.modules as modules
from pynzor.core.events import ProgressEvent


def assert_progress_contract(events: list[ProgressEvent], module: str) -> None:
    """Assert an event stream is well-formed for a live progress bar."""
    assert events, f"{module} emitted no progress events"
    assert all(e.module == module for e in events)

    dones = [e.done for e in events]
    assert dones == sorted(dones), f"{module} progress went backwards: {dones}"
    assert all(0 <= e.done <= e.total for e in events), f"{module} done outside 0..total"

    final = events[-1]
    assert final.done == final.total, (
        f"{module} finished at {final.done}/{final.total}; a bar would never fill"
    )


async def test_ports_progress_and_result_parity():
    """Port scanning reports one event per port and returns the same result."""
    events: list[ProgressEvent] = []
    ports = [80, 443, 22]

    with_cb = await modules.scan("127.0.0.1", ports=ports, on_progress=events.append)
    without_cb = await modules.scan("127.0.0.1", ports=ports)

    assert_progress_contract(events, "ports")
    assert len(events) == len(ports)
    assert events[-1].total == len(ports)
    assert [(p.port, p.status) for p in with_cb.ports] == [
        (p.port, p.status) for p in without_cb.ports
    ]


async def test_fuzz_progress_streams_hits(http_fixture, test_wordlist):
    """Directory fuzzing emits per-request events, carrying hits as they land."""
    events: list[ProgressEvent] = []

    with_cb = await modules.fuzz(
        http_fixture, str(test_wordlist), threads=5, on_progress=events.append
    )
    without_cb = await modules.fuzz(http_fixture, str(test_wordlist), threads=5)

    request_events = [e for e in events if e.note is None]
    assert_progress_contract(request_events, "fuzz")

    # /admin is the fixture's only hit, and it must arrive on the event stream
    # rather than only in the final result.
    streamed = [e.item.url for e in request_events if e.item is not None]
    assert [r.url for r in with_cb.found] == streamed
    assert [r.url for r in without_cb.found] == streamed


async def test_fuzz_progress_notes_baseline_phase(http_fixture, test_wordlist):
    """The baseline probe is announced, so the UI isn't blank while it runs."""
    events: list[ProgressEvent] = []
    await modules.fuzz(
        http_fixture, str(test_wordlist), threads=5, use_baseline=True, on_progress=events.append
    )
    assert any(e.note and "baseline" in e.note for e in events)


async def test_headers_progress(http_fixture):
    """Header analysis is a single request, so it reports 0/1 then 1/1."""
    events: list[ProgressEvent] = []

    with_cb = await modules.analyze(http_fixture, on_progress=events.append)
    without_cb = await modules.analyze(http_fixture)

    assert [(e.done, e.total) for e in events] == [(0, 1), (1, 1)]
    assert_progress_contract(events, "headers")
    assert with_cb.grade == without_cb.grade
    assert with_cb.score == without_cb.score


@pytest.mark.parametrize(
    "call,module,path",
    [
        (modules.probe, "sqli", "/sqli?id=1"),
        (modules.detect, "xss", "/xss?q=1"),
    ],
)
async def test_probe_progress(http_fixture, call, module, path):
    """The vuln probes report one event per payload test and stay deterministic."""
    events: list[ProgressEvent] = []
    target = f"{http_fixture}{path}"

    with_cb = await call(target, on_progress=events.append)
    without_cb = await call(target)

    assert_progress_contract(events, module)
    assert with_cb.vulnerable == without_cb.vulnerable is True
    assert len(with_cb.vulnerabilities) == len(without_cb.vulnerabilities)


async def test_subdomain_progress_counts_completions():
    """Subdomain enumeration counts completions, not starts, and notes the wildcard probe."""
    events: list[ProgressEvent] = []
    wordlist = ["pynzor-nx-a", "pynzor-nx-b", "pynzor-nx-c"]

    await modules._subdomain.enumerate_subdomains(
        "example.invalid",
        wordlist,
        threads=3,
        check_http=False,
        on_progress=events.append,
    )

    assert any(e.note and "wildcard" in e.note for e in events)
    resolves = [e for e in events if e.note is None]
    assert_progress_contract(resolves, "subdomain")
    assert len(resolves) == len(wordlist)


async def test_callback_exception_does_not_break_a_scan():
    """A frontend that raises inside the callback must not take the scan down."""

    def exploding(_event):
        raise RuntimeError("frontend bug")

    result = await modules.scan("127.0.0.1", ports=[80, 443], on_progress=exploding)
    assert len(result.ports) == 2
