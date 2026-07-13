"""Pynzor - CTF/lab web recon CLI for authorized testing."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("Pynzor")
except PackageNotFoundError:  # pragma: no cover - source checkout without install
    __version__ = "0.0.0"

__all__ = ["__version__"]
