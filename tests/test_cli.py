import io
import os
import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

from pynzor.cli import main as main_module
from pynzor.cli.commands import app, load_config


runner = CliRunner()


def test_help_exposes_headers_command_not_internal_name():
    """The public docs command is `headers`; the Python function name must not leak."""
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "headers" in result.output
    assert "headers-cmd" not in result.output


def test_version_flag_prints_package_name():
    """--version exits cleanly with a package-style version line."""
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.output.startswith("Pynzor ")


def test_default_config_resolves_bundled_wordlists():
    """Default config paths resolve relative to pynzor/cli/config.yaml."""
    config = load_config()

    assert Path(config["fuzzer"]["wordlist"]).is_file()
    assert Path(config["subdomain"]["wordlist"]).is_file()
    assert Path(config["wordlists"]["directories"]).is_file()
    assert Path(config["wordlists"]["parameters"]).is_file()
    assert Path(config["wordlists"]["subdomains"]).is_file()


def _cp1252_stream() -> io.TextIOWrapper:
    """A text stream with Windows' default legacy code page.

    cp1252 cannot encode the block characters in the banner, which is exactly
    what a Windows console hands the process unless it has been switched to
    UTF-8. Reproducing it here rather than skipping-unless-Windows means the
    regression is caught on every platform CI runs on.
    """
    return io.TextIOWrapper(io.BytesIO(), encoding="cp1252", newline="")


def test_ascii_banner_is_encodable_by_a_legacy_code_page():
    """The fallback has to be representable everywhere, or it is not a fallback."""
    assert main_module.ASCII_BANNER.isascii()
    assert main_module.ASCII_BANNER.encode("cp1252")
    # Derived from the real banner, so it keeps the wordmark's shape instead of
    # degrading to a bare string.
    assert main_module.ASCII_BANNER.count("\n") == main_module.BANNER.count("\n")


def test_banner_falls_back_instead_of_crashing_on_a_legacy_code_page():
    """`print(BANNER)` to a cp1252 console raised UnicodeEncodeError.

    That took down every command except `--version` -- the one path that skips
    the banner -- on every Windows binary Pynzor has shipped. Rich raises on the
    same stream, so printing through it is not a fix; the fallback is.
    """
    stream = _cp1252_stream()

    main_module.print_banner(file=stream)

    stream.flush()
    written = stream.buffer.getvalue().decode("cp1252")
    assert "#" in written, "expected the ASCII wordmark, got nothing usable"


def test_banner_is_unchanged_on_a_utf8_console():
    """A capable console still gets the real block-character banner."""
    stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", newline="")

    main_module.print_banner(file=stream)

    stream.flush()
    assert "█" in stream.buffer.getvalue().decode("utf-8")


def test_cli_runs_under_a_legacy_code_page():
    """End-to-end guard for the failure that broke the v1.2.0 Windows build.

    PYTHONIOENCODING=cp1252 gives the interpreter the same stdout encoding a
    Windows console does, so this reproduces the release failure on Linux and
    macOS in about a second -- the Windows binary is only built at release time,
    which is why the bug reached a tag before anyone saw it.
    """
    env = {**os.environ, "PYTHONIOENCODING": "cp1252"}

    result = subprocess.run(
        [sys.executable, "-m", "pynzor", "--help"],
        capture_output=True,
        text=True,
        env=env,
    )

    assert result.returncode == 0, f"stderr:\n{result.stderr}"
    assert "Usage" in result.stdout
    assert "UnicodeEncodeError" not in result.stderr
