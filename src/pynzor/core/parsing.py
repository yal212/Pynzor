"""Option parsers shared by the CLI and the TUI.

These raise plain ``ValueError`` so the TUI can show the message inline while
``cli/commands.py`` re-raises it as ``typer.BadParameter``.
"""


def parse_int_list(value: str | None, param: str = "value") -> list[int] | None:
    """Parse a comma-separated string of integers.

    Args:
        value: Comma-separated integers, or None/empty.
        param: Parameter name used in error messages.

    Returns:
        The parsed list, or None if ``value`` is empty.

    Raises:
        ValueError: If any element is not an integer.
    """
    if not value:
        return None
    try:
        return [int(p.strip()) for p in value.split(",") if p.strip()]
    except ValueError:
        raise ValueError(f"expected comma-separated integers, got: {value!r}")


def parse_str_list(value: str | None) -> list[str] | None:
    """Parse a comma-separated string into a list of trimmed strings.

    Args:
        value: Comma-separated values, or None/empty.

    Returns:
        The parsed list, or None if ``value`` is empty.
    """
    if not value:
        return None
    return [p.strip() for p in value.split(",") if p.strip()]


def parse_headers(values: list[str] | None) -> dict[str, str]:
    """Parse ``Name: value`` header strings into a dict.

    Args:
        values: Header strings, each in ``Name: value`` form.

    Returns:
        A mapping of header name to value.

    Raises:
        ValueError: If any entry lacks a colon separator.
    """
    headers: dict[str, str] = {}
    for raw in values or []:
        if ":" not in raw:
            raise ValueError(f"Invalid header (expected 'Name: value'): {raw}")
        name, _, val = raw.partition(":")
        headers[name.strip()] = val.strip()
    return headers
