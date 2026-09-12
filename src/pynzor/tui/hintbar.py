"""The bottom bar: what the focused panel can do, and who we are.

lazygit spends its last row on the keys that work *here*, not on a fixed global
set, which is the difference between a bar you read and a bar you stop seeing.
Transient status messages borrow the same row rather than claiming one of their
own -- rows are the scarcest thing in an 80x24 terminal.
"""

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Static

from pynzor import __version__
from pynzor.tui.keymap import PanelId, escape_markup, hints_for


class HintBar(Horizontal):
    """One row: contextual keys on the left, app and version on the right."""

    def __init__(self) -> None:
        super().__init__(id="hintbar")
        self._text = ""

    def compose(self) -> ComposeResult:
        """A flexible hint area and a fixed-width brand.

        The brand never changes, so it can be `width: auto` without ever
        costing a layout pass; the hints are `1fr` so repainting them with
        `layout=False` is safe no matter how long the text gets.
        """
        yield Static("", id="hints")
        yield Static(f"Pynzor {__version__}", id="brand")

    def show_hints(self, panel: PanelId) -> None:
        """Paint the keys available in ``panel``."""
        # lazygit's spelling -- `<key>: label` in optionsTextColor blue, joined
        # by a comma. Two characters of separator rather than six matters: the
        # row is ellipsis-truncated, so every character the separators take is
        # one fewer key the user can see at 80 columns.
        # Escaped: `[` and `]` are bound keys, and Rich would read them as a tag.
        cells = [f"[$accent]{escape_markup(key.shown)}[/]: {key.label}" for key in hints_for(panel)]
        self._text = ", ".join(cells)
        self.query_one("#hints", Static).update(self._text, layout=False)

    def show_status(self, message: str, level: str = "info") -> None:
        """Borrow the row for a transient message.

        ``level`` picks the colour: an error that reads the same as a hint is
        an error nobody notices.
        """
        colour = {"error": "$error", "warn": "$warning"}.get(level, "$success")
        self._text = f"[{colour}]{escape_markup(message)}[/]"
        self.query_one("#hints", Static).update(self._text, layout=False)

    @property
    def text(self) -> str:
        """Whatever the bar is currently showing, for tests."""
        return self._text
