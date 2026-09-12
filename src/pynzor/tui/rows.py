"""Turn module results into table rows, and rows back into detail text.

Kept free of Textual so the row shape can be unit-tested directly. Two entry
points that must agree:

* :func:`row_for` renders one finding as it streams in off a progress event.
* :func:`rows_from_result` rebuilds the whole table from the finished result.

The table is rebuilt from the result when a module completes, so what is on
screen always matches the exported report even if events were dropped.
"""

from dataclasses import fields, is_dataclass
from typing import Any

Row = tuple[str, ...]


def _text(value: Any, dash: str = "-") -> str:
    """Render a cell value, collapsing None/empty to a dash."""
    if value is None or value == "":
        return dash
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def _truncate(value: Any, limit: int) -> str:
    """Render a cell value clipped to ``limit`` characters."""
    text = _text(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def row_for(module_id: str, item: Any) -> Row | None:
    """Render one streamed finding as a table row.

    Args:
        module_id: Which module produced the item.
        item: The object carried on a ``ProgressEvent``, possibly None.

    Returns:
        The row, or None when the item is not a finding worth showing (a
        closed port, a miss, or a whole-result object).
    """
    if item is None:
        return None

    if module_id == "ports":
        if getattr(item, "status", None) == "closed":
            return None
        version = " ".join(x for x in (item.product, item.version) if x)
        return (str(item.port), item.status, _text(item.service), _text(version))

    if module_id == "fuzz":
        return (
            str(item.status_code),
            _text(item.url),
            str(item.content_length),
            _text(item.redirect),
        )

    if module_id == "subdomain":
        return (item.subdomain, item.record_type, _truncate(item.value, 40), _text(item.verified))

    if module_id in ("sqli", "xss"):
        # A probe unit that found nothing resolves to None, not a finding.
        if not hasattr(item, "payload"):
            return None
        return (
            _text(item.type),
            _truncate(item.payload, 40),
            _truncate(item.url, 50),
            _truncate(item.evidence, 60),
        )

    return None


def rows_from_result(module_id: str, result: Any) -> list[tuple[Any, Row]]:
    """Rebuild a module's full table from its finished result.

    Returns:
        ``(finding_object, row)`` pairs in report order, so selecting a row
        gives the drill-down pane the original dataclass.
    """
    if result is None:
        return []

    if module_id == "ports":
        items = [p for p in result.ports if p.status != "closed"]
    elif module_id == "fuzz":
        items = list(result.found)
    elif module_id == "subdomain":
        items = list(result.subdomains)
    elif module_id in ("sqli", "xss"):
        items = list(result.vulnerabilities)
    elif module_id == "headers":
        # Missing headers are the findings; present ones are not actionable.
        return [
            (a, (a.header, _text(a.present), a.risk, _truncate(a.recommendation, 60)))
            for a in result.analysis
            if not a.present
        ]
    else:
        return []

    pairs = []
    for item in items:
        row = row_for(module_id, item)
        if row is not None:
            pairs.append((item, row))
    return pairs


def headline(module_id: str, result: Any) -> str:
    """One-line verdict for a finished module, shown above its table."""
    if result is None:
        return ""
    if module_id == "ports":
        open_count = len([p for p in result.ports if p.status == "open"])
        return f"{open_count} open of {len(result.ports)} scanned"
    if module_id == "fuzz":
        return f"{len(result.found)} hits in {result.scanned} requests ({result.mode} mode)"
    if module_id == "headers":
        return f"score {result.score}/100 — grade {result.grade}"
    if module_id in ("sqli", "xss"):
        verdict = "VULNERABLE" if result.vulnerable else "no indicators"
        return f"{verdict} — {result.tested} payloads tested"
    if module_id == "subdomain":
        wildcard = " (wildcard DNS detected)" if result.wildcard_detected else ""
        return f"{len(result.subdomains)} found in {result.scanned} checked{wildcard}"
    return ""


def detail_lines(item: Any) -> list[tuple[str, str]]:
    """Expand a finding into ``(label, value)`` pairs for the drill-down pane.

    Reads the dataclass fields directly, so evidence, banners, payloads, and
    recommendations the summary tables clip are all shown in full.
    """
    if item is None:
        return []
    if not is_dataclass(item):
        return [("value", str(item))]
    return [
        (f.name.replace("_", " "), _text(getattr(item, f.name)))
        for f in fields(item)
        if getattr(item, f.name) not in (None, "")
    ]
