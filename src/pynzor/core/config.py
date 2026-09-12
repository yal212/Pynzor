from pathlib import Path


def load_config(config_path: Path | None = None) -> dict:
    """Load the YAML config, resolving relative wordlist paths.

    Relative ``wordlist`` paths (under ``fuzzer``/``subdomain`` and the
    ``wordlists`` map) are resolved against the config file's directory so the
    CLI works when run as a bundled executable.

    Args:
        config_path: Path to a config file; defaults to the bundled
            ``config.yaml`` shipped in ``pynzor.cli``.

    Returns:
        The parsed configuration dict.
    """
    import yaml

    default_config = Path(__file__).parent.parent / "cli" / "config.yaml"
    config_file_path = config_path or default_config
    config_base = config_file_path.parent

    with open(config_file_path, encoding="utf-8") as f:
        config = yaml.safe_load(f)

    # Resolve relative wordlist paths against the config file's directory.
    # Required when running as a PyInstaller exe: CWD != bundle root (_MEIPASS).
    for section in ("fuzzer", "subdomain"):
        wl = config.get(section, {}).get("wordlist")
        if wl and not Path(wl).is_absolute():
            config[section]["wordlist"] = str(config_base / wl)
    for key, wl in config.get("wordlists", {}).items():
        if wl and not Path(wl).is_absolute():
            config["wordlists"][key] = str(config_base / wl)

    return config
