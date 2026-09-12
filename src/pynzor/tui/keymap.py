"""Every key the dashboard binds, in one table.

Four things used to be hand-maintained copies of each other: the app's
``BINDINGS``, the ``?`` cheatsheet, the bottom hint bar, and the README. Here
they are one table and three generators, so a key can only be added in one
place.

``UNIVERSAL`` holds the keys that work anywhere. ``PANELS`` holds the ones that
mean something only while a particular side panel has focus -- that split is
what makes the hint bar context-sensitive, the way lazygit's is.

Actions are written against the app (``app.`` prefixed where a panel binds
them), because Textual resolves an action along the focus chain: the focused
widget, then its ancestors, then the screen, then the app.
"""

from dataclasses import dataclass

from textual.binding import Binding, BindingType

PanelId = str

#: Side panels in the order they stack, which is also their ``1``-``5`` order.
PANEL_ORDER: tuple[PanelId, ...] = ("status", "modules", "options", "findings", "reports")

#: Panel id -> its title. The border draws this behind the panel's jump number
#: (lazygit's showPanelJumps); bare here because the cheatsheet's section
#: headings come from the same table and are compared against the README.
PANEL_TITLES: dict[PanelId, str] = {
    "status": "Status",
    "modules": "Modules",
    "options": "Options",
    "findings": "Findings",
    "reports": "Reports",
}

#: How a key reads in the hint bar and the cheatsheet. Anything not here is
#: shown as-is, so ordinary letters stay bare the way lazygit writes them.
_DISPLAY = {
    "space": "<space>",
    "enter": "<enter>",
    "escape": "<esc>",
    "tab": "<tab>",
    "shift+tab": "<s-tab>",
    "ctrl+d": "<c-d>",
    "ctrl+u": "<c-u>",
    "ctrl+p": "<c-p>",
    "question_mark": "?",
    "comma": ",",
    "full_stop": ".",
    "down": "<down>",
    "up": "<up>",
    "left": "<left>",
    "right": "<right>",
}


@dataclass(frozen=True)
class Key:
    """One bound key: what Textual binds, and how it is described."""

    keys: str
    """Textual's comma-separated key string, e.g. ``"j,down"``."""

    action: str
    """The action to run, e.g. ``"nav('down')"`` or ``"app.run"``."""

    label: str
    """Terse description. The cheatsheet has to fit 80x24 in two columns."""

    hint: bool = True
    """Show in the bottom hint bar. Navigation keys set this False: lazygit
    does not spend bar width on the arrow keys either."""

    display: str = ""
    """Override for how the key column reads; derived from ``keys`` when blank."""

    @property
    def key_list(self) -> list[str]:
        """The individual keys this binds, aliases included."""
        return [k.strip() for k in self.keys.split(",") if k.strip()]

    @property
    def shown(self) -> str:
        """How the key column reads. Only the first alias is advertised.

        ``"j,down"`` exists so muscle memory works, but a cheatsheet that lists
        both spellings of every key is twice as long and no more useful.
        """
        if self.display:
            return self.display
        first = self.key_list[0]
        return _DISPLAY.get(first, first)

    @property
    def binding(self) -> Binding:
        """The Textual binding. Never ``show``: the hint bar replaces Footer."""
        return Binding(self.keys, self.action, self.label, show=False)


# --------------------------------------------------------------------- tables

#: The universal keys, grouped the way the cheatsheet lists them. One flat
#: block of twenty-five rows does not fit a card next to five small panel
#: sections -- and the groups are how you look a key up anyway.
UNIVERSAL_GROUPS: tuple[tuple[str, tuple[Key, ...]], ...] = (
    (
        "Panels",
        (
            # lazygit numbers its side panels and so do we; the digits are
            # documented rather than drawn into the borders.
            Key("1", "app.focus_panel('status')", "Status panel", hint=False),
            Key("2", "app.focus_panel('modules')", "Modules panel", hint=False),
            Key("3", "app.focus_panel('options')", "Options panel", hint=False),
            Key("4", "app.focus_panel('findings')", "Findings panel", hint=False),
            Key("5", "app.focus_panel('reports')", "Reports panel", hint=False),
            Key("tab", "app.next_panel", "Next panel", hint=False),
            Key("shift+tab", "app.prev_panel", "Previous panel", hint=False),
            # lazygit's prevBlock/nextBlock: the column and the main panel are
            # two blocks, and h/l move between them the way they move between
            # windows in vim.
            Key("l,right", "app.next_block", "Focus main panel", hint=False),
            Key("h,left", "app.prev_block", "Focus side panel", hint=False),
            Key("0", "app.focus_main", "Main view", hint=False),
        ),
    ),
    (
        "Navigation",
        (
            Key("j,down", "app.nav('down')", "Down", hint=False),
            Key("k,up", "app.nav('up')", "Up", hint=False),
            Key("g", "app.nav('home')", "Top", hint=False),
            Key("G", "app.nav('end')", "Bottom", hint=False),
            # Spelled by name, not as "," -- `keys` is itself comma-separated, so a
            # literal comma would parse as two empty aliases. `full_stop` comes
            # along for the ride so the pair reads as a pair.
            Key("full_stop", "app.nav('pagedown')", "Page down", hint=False),
            Key("comma", "app.nav('pageup')", "Page up", hint=False),
            # The main panel scrolls without taking focus off the side panel --
            # the lazygit reflex that makes a long result readable one-handed.
            # `J`/`K` are lazygit's alt spelling; only the first alias is ever
            # advertised, so they cost nothing in the bar or the cheatsheet.
            Key("ctrl+d,J", "app.scroll_main('down')", "Scroll main down", hint=False),
            Key("ctrl+u,K", "app.scroll_main('up')", "Scroll main up", hint=False),
            Key("escape", "app.leave_main", "Back", hint=False),
        ),
    ),
    (
        "Run",
        (
            Key("r", "app.run", "Run"),
            Key("s", "app.stop", "Stop", hint=False),
            Key("e", "app.export", "Export reports", hint=False),
            Key("c", "app.copy_command", "Copy CLI command", hint=False),
        ),
    ),
    (
        "View",
        (
            Key("+", "app.grow_main", "Bigger main panel", hint=False),
            Key("_", "app.shrink_main", "Smaller main panel", hint=False),
            Key("@", "app.toggle_log", "Command log", hint=False),
            Key("/", "app.filter", "Filter", hint=False),
        ),
    ),
    (
        "App",
        (
            Key("x", "app.menu", "Menu"),
            Key("question_mark", "app.help", "Keybindings"),
            Key("ctrl+p", "app.command_palette", "Command palette", hint=False),
            Key("q", "app.quit", "Quit", hint=False),
        ),
    ),
)

#: Every universal key, flat, in group order.
UNIVERSAL: tuple[Key, ...] = tuple(key for _, keys in UNIVERSAL_GROUPS for key in keys)

PANELS: dict[PanelId, tuple[Key, ...]] = {
    "status": (Key("enter,i,t", "app.edit_target", "Set target", display="<enter>"),),
    "modules": (
        Key("space", "app.toggle_module", "Toggle module"),
        Key("enter", "app.focus_results", "Open results"),
        Key("]", "app.next_subtab", "Next tab", hint=False),
        Key("[", "app.prev_subtab", "Previous tab", hint=False),
    ),
    "options": (
        Key("enter", "app.edit_option", "Edit value"),
        Key("d", "app.reset_option", "Reset to config default"),
    ),
    "findings": (Key("enter", "app.focus_results", "Expand"),),
    "reports": (
        Key("enter", "app.open_report", "Open report"),
        Key("d", "app.refresh_reports", "Refresh listing"),
    ),
}


# ----------------------------------------------------------------- generators


def escape_markup(text: str) -> str:
    """Escape text so Textual's markup parser renders it literally.

    ``[`` is itself a bound key here. Rich's own ``escape`` leaves a lone ``[``
    untouched, and a trailing one then merges with whatever tag follows it --
    ``[`` immediately before a closing ``[/]`` renders as ``[[/]``.
    """
    return text.replace("[", "\\[")


def bindings_for(panel: PanelId) -> list[BindingType]:
    """Textual bindings for one side panel's contextual keys.

    Typed as ``BindingType`` rather than ``Binding``: that is what Textual
    declares ``BINDINGS`` to be, and ``list`` is invariant.
    """
    return [key.binding for key in PANELS[panel]]


def universal_bindings() -> list[BindingType]:
    """Textual bindings for the keys that work everywhere."""
    return [key.binding for key in UNIVERSAL]


def hints_for(panel: PanelId) -> list[Key]:
    """The keys the bottom bar advertises while ``panel`` has focus.

    Panel keys first, then the two doors out of not knowing what to press --
    exactly what lazygit keeps pinned at the right of its bar.
    """
    keys = [key for key in PANELS.get(panel, ()) if key.hint]
    keys += [key for key in UNIVERSAL if key.hint]
    return keys


def menu_for(panel: PanelId) -> list[tuple[str, str, str]]:
    """``(shown, label, action)`` for every key the ``x`` menu offers.

    Panel keys first so the context-specific ones are what the cursor lands on,
    then the universal set. Navigation is left out: a menu row that moves the
    cursor is a menu row nobody picks.
    """
    rows = [(key.shown, key.label, key.action) for key in PANELS.get(panel, ())]
    rows += [
        (key.shown, key.label, key.action)
        for key in UNIVERSAL
        if key.action.removeprefix("app.").split("(")[0] not in ("nav", "focus_panel")
    ]
    return rows


def sections() -> list[tuple[str, list[tuple[str, str]]]]:
    """The cheatsheet, grouped the way the keys are actually scoped.

    The universal groups first, then one section per panel -- which is both
    lazygit's grouping and the only grouping that stays true as keys move
    between scopes.
    """
    grouped: list[tuple[str, list[tuple[str, str]]]] = [
        (group, [(key.shown, key.label) for key in keys]) for group, keys in UNIVERSAL_GROUPS
    ]
    grouped += [
        (PANEL_TITLES[panel], [(key.shown, key.label) for key in PANELS[panel]])
        for panel in PANEL_ORDER
        if PANELS.get(panel)
    ]
    return grouped


def all_keys() -> list[Key]:
    """Every ``Key`` in the table, universal and panel-scoped alike."""
    return [*UNIVERSAL, *(key for panel in PANEL_ORDER for key in PANELS.get(panel, ()))]


def documented_actions() -> set[str]:
    """Every action the table binds, normalised to its bare action name.

    The drift guard compares this against the actions actually bound on the app
    and its panels, so a hand-written ``Binding`` anywhere fails the build.
    """
    return {key.action.removeprefix("app.") for key in all_keys()}
