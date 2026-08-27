"""The dashboard's own colour palette.

Textual resolves ``$accent``, ``$success`` and friends against whatever theme is
active, which otherwise depends on the user's terminal and Textual's default of
the day. Pinning one theme means the rail glyphs, the progress bar, and the
focused-panel border read the same everywhere.

Registered -- not forced: the command palette's theme switcher still works, so
anyone who prefers gruvbox keeps it for the rest of the session.
"""

from textual.theme import Theme

PYNZOR_THEME = Theme(
    name="pynzor",
    primary="#7aa2f7",
    secondary="#3d59a1",
    accent="#7dcfff",
    warning="#e0af68",
    error="#f7768e",
    success="#9ece6a",
    foreground="#c0caf5",
    background="#16161e",
    surface="#1a1b26",
    panel="#232433",
    dark=True,
    variables={
        "footer-key-foreground": "#7dcfff",
        "block-cursor-background": "#7aa2f7",
        "block-cursor-foreground": "#16161e",
        "block-cursor-text-style": "none",
    },
)
