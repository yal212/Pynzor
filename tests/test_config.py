"""Config loading: a --config file is an overlay on the bundled defaults.

Covers `#17 <https://github.com/yal212/Pynzor/issues/17>`_ -- a partial config
used to crash with an unhandled KeyError on the first section it omitted.
"""

from pathlib import Path

import pytest

from pynzor.core.config import load_config


@pytest.fixture
def write(tmp_path):
    """Write a config file into a temp dir and return its path."""

    def _write(text: str, name: str = "partial.yaml") -> Path:
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        return path

    return _write


def test_no_path_loads_the_bundled_default():
    """The default config is complete and its wordlists are absolute."""
    config = load_config()
    assert config["scanner"]["common_ports"]
    assert Path(config["fuzzer"]["wordlist"]).is_absolute()
    assert Path(config["fuzzer"]["wordlist"]).exists()


def test_partial_config_keeps_every_untouched_section(write):
    """#17's reproduction: one key changed, nothing else lost."""
    config = load_config(write("sqli:\n  rate_limit: 0.5\n"))

    assert config["sqli"]["rate_limit"] == 0.5
    # The three sections whose direct lookups used to raise KeyError.
    assert config["scanner"]["common_ports"]
    assert config["fuzzer"]["wordlist"]
    assert config["fuzzer"]["threads"]
    assert config["subdomain"]["wordlist"]
    assert config["subdomain"]["threads"]


def test_partial_section_keeps_its_sibling_keys(write):
    """Merging is per key, not per section."""
    default = load_config()
    config = load_config(write("fuzzer:\n  threads: 99\n"))

    assert config["fuzzer"]["threads"] == 99
    assert config["fuzzer"]["extensions"] == default["fuzzer"]["extensions"]
    assert config["fuzzer"]["wordlist"] == default["fuzzer"]["wordlist"]


def test_lists_replace_rather_than_append(write):
    """A list in the overlay means exactly that list."""
    config = load_config(write("scanner:\n  common_ports: [80]\n"))
    assert config["scanner"]["common_ports"] == [80]


def test_copied_config_inherits_the_bundled_wordlist_paths(write):
    """A config elsewhere on disk still finds the shipped wordlists.

    The paths it does not override are resolved against the *bundle*, not
    against the copy's directory -- the sharp edge #17 lists under Related.
    """
    config = load_config(write("fuzzer:\n  rate_limit: 0\n"))

    for section in ("fuzzer", "subdomain"):
        wordlist = Path(config[section]["wordlist"])
        assert wordlist.is_absolute()
        assert wordlist.exists()
    for wordlist in config["wordlists"].values():
        assert Path(wordlist).exists()


def test_user_relative_wordlist_resolves_beside_its_own_file(write, tmp_path):
    """An overridden relative path still resolves against the user's file."""
    config = load_config(write("fuzzer:\n  wordlist: mine/words.txt\n"))
    assert config["fuzzer"]["wordlist"] == str(tmp_path / "mine" / "words.txt")


def test_user_absolute_wordlist_is_left_alone(write, tmp_path):
    """An absolute path is taken as given."""
    absolute = tmp_path / "elsewhere" / "words.txt"
    config = load_config(write(f"subdomain:\n  wordlist: {absolute}\n"))
    assert config["subdomain"]["wordlist"] == str(absolute)


def test_empty_file_changes_nothing(write):
    """yaml.safe_load returns None for an empty file; that is a valid overlay."""
    assert load_config(write("")) == load_config()


def test_non_mapping_config_is_a_clean_error(write):
    """A top-level list names the file instead of raising AttributeError."""
    path = write("- not a mapping\n")
    with pytest.raises(ValueError, match="must contain a mapping") as excinfo:
        load_config(path)
    assert str(path) in str(excinfo.value)


def test_malformed_yaml_is_a_clean_error(write):
    """A parse failure names the file rather than surfacing yaml's own error."""
    path = write("fuzzer:\n  threads: [1,\n")
    with pytest.raises(ValueError, match="not valid YAML"):
        load_config(path)


def test_missing_file_raises_oserror(write, tmp_path):
    """A path that does not exist stays an OSError for the CLI to translate."""
    with pytest.raises(OSError):
        load_config(tmp_path / "nope.yaml")
