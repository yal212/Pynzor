"""Typer-free service layer shared by the CLI and the TUI.

Everything here is importable without pulling in Typer or touching a console,
so both frontends drive the same option resolution, the same async module
calls, and the same report envelopes.
"""
