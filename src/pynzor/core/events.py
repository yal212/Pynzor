from dataclasses import dataclass
from typing import Any, Callable, Optional


@dataclass(frozen=True)
class ProgressEvent:
    """One unit of work completed inside a module's async fan-out.

    Emitted from inside the ``asyncio.gather`` loops so a frontend can draw a
    live bar and stream hits in as they are found. The callback is deliberately
    synchronous and cheap: it fires while a semaphore slot is held, so it must
    never await or block. A Textual frontend should do nothing but
    ``post_message`` from it.

    Attributes:
        module: Module id ("ports", "fuzz", "headers", "sqli", "xss",
            "subdomain").
        done: Units completed so far. Monotonically non-decreasing.
        total: Units expected in total. Reflects any budget cap the module
            applies, so ``done`` always reaches ``total``.
        item: The result object for this unit when it is a hit worth showing
            (``PortResult``, ``FuzzResult``, ``SubdomainResult``, ...), else None.
        note: Optional human-readable phase label, e.g. "probing baseline".
    """

    module: str
    done: int
    total: int
    item: Any = None
    note: Optional[str] = None


ProgressCallback = Callable[[ProgressEvent], None]


def emit(
    on_progress: Optional[ProgressCallback],
    module: str,
    done: int,
    total: int,
    item: Any = None,
    note: Optional[str] = None,
) -> None:
    """Fire a progress callback if one was supplied, swallowing frontend errors.

    A broken callback must never take down a scan, so exceptions raised by the
    consumer are dropped rather than propagated into the gather.
    """
    if on_progress is None:
        return
    try:
        on_progress(ProgressEvent(module, done, total, item, note))
    except Exception:
        pass


def track(
    coros: list,
    on_progress: Optional[ProgressCallback],
    module: str,
) -> list:
    """Wrap coroutines so each emits a progress event the moment it completes.

    Used by the probe modules, whose fan-out unit is a whole payload test
    rather than a single request. The awaited value is passed through as the
    event's ``item``, so a frontend can stream findings in as they land.

    Args:
        coros: Coroutines about to be handed to ``asyncio.gather``.
        on_progress: Callback to fire, or None to pass the list through.
        module: Module id recorded on each event.

    Returns:
        The wrapped coroutines, in the same order.
    """
    if on_progress is None:
        return coros

    total = len(coros)
    counter = {"done": 0}

    async def wrapped(coro):
        """Await one unit of work, then report it as done."""
        result = await coro
        counter["done"] += 1
        emit(on_progress, module, counter["done"], total, result)
        return result

    return [wrapped(c) for c in coros]
