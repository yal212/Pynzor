from pathlib import Path
from typing import Any


def load_config(config_path: Path | None = None) -> dict:
    """Load the YAML config, merged over the bundled defaults.

    A file passed with ``--config`` is an *overlay*: it is deep-merged onto the
    bundled ``config.yaml``, so it only has to carry the keys it changes. A
    partial file used to crash on the first section it omitted
    (`#17 <https://github.com/yal212/Pynzor/issues/17>`_).

    Relative ``wordlist`` paths (under ``fuzzer``/``subdomain`` and the
    ``wordlists`` map) are resolved against their own file's directory before
    the merge, so bundled paths stay bundle-relative -- a copied config that
    does not override them keeps pointing at the shipped wordlists -- while a
    user's own relative path still resolves beside the user's file.

    Args:
        config_path: Path to an overlay config file; when None, only the
            bundled ``config.yaml`` shipped in ``pynzor.cli`` is loaded.

    Returns:
        The parsed configuration dict.

    Raises:
        ValueError: If a config file is not valid YAML, or does not hold a
            mapping at its top level.
    """
    config = _read(Path(__file__).parent.parent / "cli" / "config.yaml")
    if config_path is not None:
        config = _merge(config, _read(config_path))
    return config


def _read(path: Path) -> dict:
    """Parse one config file, resolving its relative wordlist paths.

    Raises:
        ValueError: If the file is not valid YAML or is not a mapping.
    """
    import yaml

    with open(path, encoding="utf-8") as f:
        try:
            config = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ValueError(f"{path} is not valid YAML: {e}")

    # An empty file is a valid overlay that changes nothing.
    if config is None:
        return {}
    if not isinstance(config, dict):
        raise ValueError(f"{path} must contain a mapping of sections, got {type(config).__name__}")

    # Resolve relative wordlist paths against the config file's directory.
    # Required when running as a PyInstaller exe: CWD != bundle root (_MEIPASS).
    base = path.parent
    for section in ("fuzzer", "subdomain"):
        wl = config.get(section, {}).get("wordlist")
        if wl and not Path(wl).is_absolute():
            config[section]["wordlist"] = str(base / wl)
    for key, wl in config.get("wordlists", {}).items():
        if wl and not Path(wl).is_absolute():
            config["wordlists"][key] = str(base / wl)

    return config


def _merge(base: dict, overlay: dict) -> dict:
    """Deep-merge ``overlay`` onto ``base``, returning a new dict.

    Two dicts merge key by key; anything else replaces outright, so
    ``scanner: {common_ports: [80]}`` means exactly that one port rather than
    appending to the shipped twenty.
    """
    merged: dict[str, Any] = dict(base)
    for key, value in overlay.items():
        current = merged.get(key)
        merged[key] = (
            _merge(current, value)
            if isinstance(current, dict) and isinstance(value, dict)
            else value
        )
    return merged
