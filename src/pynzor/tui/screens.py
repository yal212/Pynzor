"""The modal popups: cheatsheet, action menu, confirmation, and text prompt.

lazygit does everything that is not navigation through a centred popup over a
dimmed background, and it is the reason the main layout never has to make room
for a form. Text entry only exists in here, which is also what keeps the rest
of the app in a single mode: outside a popup, every key is a command.
"""

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import Input, Label, ListItem, ListView, Static

from pynzor.tui.keymap import PanelId, escape_markup, menu_for, sections


class DashboardScreen(Screen):
    """The default screen, with Textual's Tab handling taken back.

    ``Screen`` binds ``tab``/``shift+tab`` to ``focus_next``/``focus_previous``,
    and screen bindings are resolved before the app's -- so the app's own
    binding never fires. lazygit's Tab steps between panels rather than
    wandering through every focusable widget, and rebinding here is the only
    place early enough to win.
    """

    BINDINGS = [
        Binding("tab", "app.next_panel", "Next panel", show=False),
        Binding("shift+tab", "app.prev_panel", "Previous panel", show=False),
    ]


# ------------------------------------------------------------------- help


def _render_section(section: str, rows: list[tuple[str, str]], width: int) -> str:
    """One section as a single markup block: a heading over aligned key rows."""
    lines = [f"[b]{section.upper()}[/b]"]
    # Escaped, because `[` is itself a keybinding: unescaped it merges with
    # the closing tag right after it and the row renders as `[[/]`.
    lines += [f"  [$accent]{escape_markup(cell.rjust(width))}[/]   {label}" for cell, label in rows]
    return "\n".join(lines)


def _columns() -> tuple[list[str], list[str]]:
    """Split the sections into two balanced columns, in order.

    A section lands left while its own midpoint is still above the halfway mark,
    which keeps the two columns within a row or two of each other -- comparing
    the running total alone puts one section too many on the left.
    """
    grouped = sections()
    width = max(len(cell) for _, rows in grouped for cell, _ in rows)
    blocks = [(_render_section(s, rows, width), len(rows) + 2) for s, rows in grouped]
    half = sum(height for _, height in blocks) / 2
    left: list[str] = []
    right: list[str] = []
    running = 0.0
    for block, height in blocks:
        (left if running + height / 2 <= half else right).append(block)
        running += height
    return left, right


class HelpScreen(ModalScreen[None]):
    """A dimmed, centred cheatsheet grouped by the scope each key belongs to."""

    BINDINGS = [
        Binding("escape,question_mark,q", "dismiss", "Close", show=False),
        # A safety net for terminals too short even for the two-column card;
        # the app's own navigation bindings do not reach a modal screen.
        Binding("j,down", "scroll('down')", "Down", show=False),
        Binding("k,up", "scroll('up')", "Up", show=False),
    ]

    def compose(self) -> ComposeResult:
        """One Static per section rather than one per row.

        A handful of widgets instead of fifty, and the key column stays aligned
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


# ------------------------------------------------------------------- menu


class MenuRow(ListItem):
    """One runnable action in the ``x`` menu."""

    def __init__(self, shown: str, label: str, action: str, index: int) -> None:
        super().__init__(id=f"menu-{index}")
        self.action_name = action
        self._shown = shown
        self._label = label

    def compose(self) -> ComposeResult:
        """Key column, then what it does."""
        yield Horizontal(
            # Escaped for the same reason as the cheatsheet: `[` is a key.
            Label(escape_markup(self._shown), classes="menu-key"),
            Label(self._label, classes="menu-label"),
            classes="menu-line",
        )


class MenuScreen(ModalScreen[str | None]):
    """Every action available right now, pickable instead of memorised.

    lazygit's ``x``. Dismisses with the chosen action string; the app runs it,
    so this screen never needs to know what any of them do.
    """

    BINDINGS = [
        Binding("escape,x,q", "dismiss", "Close", show=False),
        Binding("j,down", "cursor('down')", "Down", show=False),
        Binding("k,up", "cursor('up')", "Up", show=False),
    ]

    def __init__(self, panel: PanelId) -> None:
        super().__init__()
        self.panel = panel

    def compose(self) -> ComposeResult:
        """The focused panel's actions first, then the universal ones."""
        with Vertical(id="menu-card"):
            yield ListView(
                *(
                    MenuRow(shown, label, action, index)
                    for index, (shown, label, action) in enumerate(menu_for(self.panel))
                ),
                id="menu-list",
            )

    def on_mount(self) -> None:
        """Label the card and put the cursor on the first row."""
        card = self.query_one("#menu-card")
        card.border_title = "Menu"
        card.border_subtitle = "enter to run · esc to close"
        self.query_one("#menu-list", ListView).focus()

    def action_cursor(self, direction: str) -> None:
        """Move the menu cursor."""
        listview = self.query_one("#menu-list", ListView)
        if direction == "down":
            listview.action_cursor_down()
        else:
            listview.action_cursor_up()

    def on_list_view_selected(self, message: ListView.Selected) -> None:
        """Hand the chosen action back to the app."""
        item = message.item
        self.dismiss(item.action_name if isinstance(item, MenuRow) else None)


# ---------------------------------------------------------------- confirm


class ConfirmScreen(ModalScreen[bool]):
    """A yes/no popup. ``enter``/``y`` confirms, ``esc``/``n`` cancels."""

    BINDINGS = [
        Binding("enter,y", "confirm", "Confirm", show=False),
        Binding("escape,n,q", "cancel", "Cancel", show=False),
    ]

    def __init__(self, title: str, question: str) -> None:
        super().__init__()
        self.title_text = title
        self.question = question

    def compose(self) -> ComposeResult:
        """The question, then what the two keys do."""
        with Vertical(id="confirm-card"):
            yield Static(self.question, id="confirm-body")
            yield Static("[$accent]enter[/] confirm    [$accent]esc[/] cancel", id="confirm-keys")

    def on_mount(self) -> None:
        """Label the card."""
        self.query_one("#confirm-card").border_title = self.title_text

    def action_confirm(self) -> None:
        """Yes."""
        self.dismiss(True)

    def action_cancel(self) -> None:
        """No."""
        self.dismiss(False)


# ----------------------------------------------------------------- prompt


class PromptScreen(ModalScreen[str | None]):
    """A one-line text popup -- the only place the app is ever in insert mode."""

    BINDINGS = [Binding("escape", "cancel", "Cancel", show=False)]

    def __init__(self, title: str, value: str = "", placeholder: str = "") -> None:
        super().__init__()
        self.title_text = title
        self.value = value
        self.placeholder = placeholder

    def compose(self) -> ComposeResult:
        """A single Input, which owns every printable key while it is up."""
        with Vertical(id="prompt-card"):
            yield Input(value=self.value, placeholder=self.placeholder, id="prompt-input")
            yield Static("[$accent]enter[/] confirm    [$accent]esc[/] cancel", id="prompt-keys")

    def on_mount(self) -> None:
        """Label the card and take focus, cursor at the end."""
        self.query_one("#prompt-card").border_title = self.title_text
        field = self.query_one("#prompt-input", Input)
        field.focus()
        field.action_end()

    def on_input_submitted(self, message: Input.Submitted) -> None:
        """Enter hands the value back."""
        self.dismiss(message.value.strip())

    def action_cancel(self) -> None:
        """Escape returns nothing, which the caller reads as 'leave it alone'."""
        self.dismiss(None)
