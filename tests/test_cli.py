from pathlib import Path

from typer.testing import CliRunner

from cli.commands import app, load_config


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
    """Default config paths resolve relative to the packaged cli/config.yaml."""
    config = load_config()

    assert Path(config["fuzzer"]["wordlist"]).is_file()
    assert Path(config["subdomain"]["wordlist"]).is_file()
    assert Path(config["wordlists"]["directories"]).is_file()
    assert Path(config["wordlists"]["parameters"]).is_file()
    assert Path(config["wordlists"]["subdomains"]).is_file()
