import sys
from typing import TextIO

from pynzor.cli.commands import app, get_version
from pynzor.core.config import load_config

BANNER = r"""
██████╗ ██╗   ██╗███╗   ██╗███████╗ ██████╗ ██████╗
██╔══██╗╚██╗ ██╔╝████╗  ██║╚══███╔╝██╔═══██╗██╔══██╗
██████╔╝ ╚████╔╝ ██╔██╗ ██║  ███╔╝ ██║   ██║██████╔╝
██╔═══╝   ╚██╔╝  ██║╚██╗██║ ███╔╝  ██║   ██║██╔══██╗
██║        ██║   ██║ ╚████║███████╗╚██████╔╝██║  ██║
╚═╝        ╚═╝   ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
"""

#: The banner's seven box-drawing and block characters, mapped onto ASCII.
#: Translated from BANNER rather than written out by hand: a second copy of the
#: wordmark is a second thing that can drift, and this way the fallback keeps
#: the shape of the real one for free.
_ASCII_FALLBACK = str.maketrans(
    {"█": "#", "═": "=", "║": "|", "╔": "+", "╗": "+", "╚": "+", "╝": "+"}
)

ASCII_BANNER = BANNER.translate(_ASCII_FALLBACK)


def _use_utf8_stdio() -> None:
    """Make stdout and stderr able to carry the characters we actually print.

    Windows hands a process its console's code page, typically cp1252 or cp437,
    and neither can encode the block characters in BANNER or the box-drawing
    characters the dashboard's borders are made of. `print(BANNER)` therefore
    raised UnicodeEncodeError and took the whole command down -- every command
    except `--version`, which is the one path that skips the banner.

    Switching the encoding is the only fix at this level: Rich raises on the
    same stream, so printing the banner through a Console instead would not
    have helped. Failures are swallowed because a stream that cannot be
    reconfigured is a cosmetic problem, and `print_banner` still degrades
    gracefully below.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8")
        except (OSError, ValueError):
            pass


def print_banner(file: TextIO | None = None) -> None:
    """Print the banner, or its ASCII equivalent on a console that cannot take it.

    The belt to `_use_utf8_stdio`'s braces: that handles the console we can
    change, this handles the one we cannot. Losing the block characters is a
    far better outcome than losing `--help`.
    """
    stream = sys.stdout if file is None else file
    try:
        print(BANNER, file=stream)
    except UnicodeEncodeError:
        print(ASCII_BANNER, file=stream)


def is_interactive() -> bool:
    """Return True when both stdin and stdout are a terminal.

    Guards the bare-invocation launch: piped, redirected, and CI runs must keep
    printing the banner and help rather than trying to start a full-screen app.
    """
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def main():
    """Launch the dashboard when run bare on a terminal, else run the CLI."""
    argv = sys.argv[1:]

    # Before anything prints, and before the dashboard starts: its borders are
    # box-drawing characters and have the same problem the banner does.
    _use_utf8_stdio()

    if not argv and is_interactive():
        from pynzor.tui.app import run_tui

        raise SystemExit(run_tui(load_config(None)))

    if "--version" not in argv:
        print_banner()
        print(f"Pynzor CLI v{get_version()}\n")
    app()


if __name__ == "__main__":
    main()
