import sys

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

    if not argv and is_interactive():
        from pynzor.tui.app import run_tui

        raise SystemExit(run_tui(load_config(None)))

    if "--version" not in argv:
        print(BANNER)
        print(f"Pynzor CLI v{get_version()}\n")
    app()


if __name__ == "__main__":
    main()
