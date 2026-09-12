"""The command log panel.

lazygit's bottom-right panel shows the git commands it just ran, which is how
you learn git by using lazygit. Pynzor's equivalent is the CLI invocation each
module corresponds to -- the dashboard is a front end for a command-line tool,
and this is where it teaches you the command line.

Appended to when a module starts or finishes, never from the progress path: a
default fuzz run emits thousands of events, and each append grows a Static and
costs a layout pass.
"""

from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.widgets import Static


class CommandLog(Vertical):
    """A scrolling transcript of what the dashboard actually ran."""

    def __init__(self) -> None:
        super().__init__(id="cmdlog")
        self._body = Static("", id="cmdlog-body")
        self._text = ""

    def compose(self) -> ComposeResult:
        """One Static in a scroller, pinned to the newest line."""
        with VerticalScroll(id="cmdlog-scroll"):
            yield self._body

    def on_mount(self) -> None:
        """Title the border."""
        self.border_title = "Command log"

    def render_lines_from(self, lines: list[str]) -> None:
        """Repaint from the session's log and scroll to the newest line."""
        self._text = "\n".join(lines)
        self._body.update(self._text)
        self.query_one("#cmdlog-scroll", VerticalScroll).scroll_end(animate=False)

    @property
    def text(self) -> str:
        """The transcript as last painted, for tests."""
        return self._text
