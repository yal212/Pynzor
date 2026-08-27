"""The keybinding cheatsheet and the modal that shows it.

``KEYMAP`` is the single source of truth for what the ``?`` overlay lists. The
app's ``BINDINGS`` remain authoritative for what the keys actually *do*; a test
asserts the two agree, because help text that silently drifts from the bindings
is worse than no help text.

Descriptions are kept terse on purpose: the card has to fit an 80x24 terminal in
two columns without scrolling, and a cheatsheet you have to scroll is one you
close.
"""

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Static

KEYMAP: list[tuple[str, list[tuple[str, str]]]] = [
    (
        "Navigation",
        [
            ("j / k", "Down / up"),
            ("g / G", "Top / bottom"),
            ("h / l", "Rail / results"),
            ("[ / ]", "Prev / next tab"),
            ("enter", "Open finding in Detail"),
            ("tab", "Cycle focus"),
        ],
    ),
    (
        "Run",
        [
            ("space", "Toggle module"),
            ("r", "Run selected modules"),
            ("s", "Stop the run"),
            ("o", "Module options"),
        ],
    ),
    (
        "Results",
        [
            ("e", "Export JSON reports"),
            ("b", "Browse saved reports"),
            ("c", "Copy CLI command"),
        ],
    ),
    (
        "Target",
        [
            ("i / t", "Edit target (insert)"),
            ("escape", "Back to normal mode"),
            ("enter", "Submit and run"),
        ],
    ),
    (
        "App",
        [
            ("?", "This help"),
            ("ctrl+p", "Command palette"),
            ("q", "Quit"),
        ],
    ),
]


def keymap_keys() -> set[str]:
    """Every individual key the cheatsheet documents.

    Cells like ``"j / k"`` describe two keys; split them so a drift test can ask
    whether one specific binding is covered.
    """
    return {
        key.strip()
        for _, rows in KEYMAP
        for cell, _ in rows
        for key in cell.split("/")
        if key.strip()
    }


def _render_section(section: str, rows: list[tuple[str, str]], width: int) -> str:
    """One section as a single markup block: a heading over aligned key rows."""
    lines = [f"[b]{section.upper()}[/b]"]
    lines += [f"  [$accent]{cell.rjust(width)}[/]   {label}" for cell, label in rows]
    return "\n".join(lines)


def _columns() -> tuple[list[str], list[str]]:
    """Split the sections into two balanced columns, in order.

    A section lands left while its own midpoint is still above the halfway mark,
    which keeps the two columns within a row or two of each other -- comparing
    the running total alone puts one section too many on the left.
    """
    width = max(len(cell) for _, rows in KEYMAP for cell, _ in rows)
    blocks = [(_render_section(s, rows, width), len(rows) + 2) for s, rows in KEYMAP]
    half = sum(height for _, height in blocks) / 2
    left: list[str] = []
    right: list[str] = []
    running = 0.0
    for block, height in blocks:
        (left if running + height / 2 <= half else right).append(block)
        running += height
    return left, right


class HelpScreen(ModalScreen[None]):
    """A dimmed, centred cheatsheet grouped by what each key is for."""

    BINDINGS = [
        Binding("escape,question_mark,q", "dismiss", "Close", show=False),
        # A safety net for terminals too short even for the two-column card;
        # the app's own navigation bindings do not reach a modal screen.
        Binding("j,down", "scroll('down')", "Down", show=False),
        Binding("k,up", "scroll('up')", "Up", show=False),
    ]

    def compose(self) -> ComposeResult:
        """One Static per section rather than one per row.

        A handful of widgets instead of forty, and the key column stays aligned
        because the padding is computed here rather than left to the layout.
        """
        with Vertical(id="help-card"):
            with VerticalScroll(id="help-scroll"):
                with Horizontal(id="help-body"):
                    for index, column in enumerate(_columns()):
                        with Vertical(classes="help-column", id=f"help-col-{index}"):
                            for block in column:
                                yield Static(block, classes="help-section")

    def on_mount(self) -> None:
        """Label the card once it exists in the DOM."""
        card = self.query_one("#help-card")
        card.border_title = "Keybindings"
        card.border_subtitle = "? or Esc to close"

    def action_scroll(self, direction: str) -> None:
        """Scroll the card when it cannot fit the terminal."""
        body = self.query_one("#help-scroll", VerticalScroll)
        if direction == "down":
            body.scroll_down(animate=False)
        else:
            body.scroll_up(animate=False)
