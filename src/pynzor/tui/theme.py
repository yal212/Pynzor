"""The dashboard's colour palette: the terminal's own.

lazygit draws in the terminal's sixteen ANSI colours and leaves the background
alone, which is why it looks native in every theme and why a translucent
terminal stays translucent behind it. This theme does the same.

The mechanism matters, because Textual has a trap here. ``background:
transparent`` is an RGBA colour with alpha 0, and alpha is dropped when a style
is converted for the terminal -- so it emits an explicit black background and
paints over exactly what it claims to let through. Only ``ansi_default`` (ANSI
index -1) survives: ANSI colours short-circuit every blend, and -1 reaches the
terminal as "emit no background at all".

``ansi=True`` is what makes the rest cooperate. It flips Textual's ``:ansi``
pseudo-class, and the built-in widgets -- Screen, ListView, DataTable -- carry
their own ``&:ansi`` rules that switch them to terminal-default backgrounds.

Registered -- not forced: the command palette's theme switcher still works, so
anyone who prefers gruvbox keeps it for the rest of the session.
"""

from textual.theme import Theme

#: lazygit's default theme block, mapped onto Textual's token names:
#: activeBorderColor green -> $success, selectedLineBgColor blue -> $primary,
#: optionsTextColor blue -> $accent, searchingActiveBorderColor cyan ->
#: $secondary, and defaultFgColor default -> every surface.
PYNZOR_THEME = Theme(
    name="pynzor",
    primary="ansi_blue",
    secondary="ansi_cyan",
    accent="ansi_blue",
    warning="ansi_yellow",
    error="ansi_red",
    success="ansi_green",
    # Foreground included: lazygit's defaultFgColor is `default` too, so text
    # comes out in whatever the terminal calls its foreground.
    foreground="ansi_default",
    background="ansi_default",
    surface="ansi_default",
    panel="ansi_default",
    boost="ansi_default",
    dark=True,
    ansi=True,
    variables={
        # Mandatory for any theme with ansi=True, not optional: Textual's own
        # Screen.DEFAULT_CSS has `&:ansi` rules referring to $ansi-background
        # and $ansi-foreground, and `ansi=True` is what switches those rules
        # on. Omit them and the stylesheet fails to parse at startup.
        "ansi-background": "ansi_black",
        "ansi-foreground": "ansi_white",
        # Textual derives $text-muted from the background, and deriving from
        # ansi_default yields ansi_default -- which would leave every "muted"
        # line indistinguishable from a normal one. Naming the dim colour
        # outright is the only way to keep the hierarchy, and it fixes the
        # stylesheet and the markup f-strings in one place.
        "text-muted": "ansi_bright_black",
        # lazygit's inactiveBorderColor.
        "border-blurred": "ansi_default",
        # The DataTable cursor. bright_white on blue rather than $text: $text
        # is ansi_default now, which carries no contrast guarantee over blue.
        "block-cursor-background": "ansi_blue",
        "block-cursor-foreground": "ansi_bright_white",
        "block-cursor-text-style": "none",
    },
)
