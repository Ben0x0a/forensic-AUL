"""Identify hub: the wizard + results viewer under one sidebar entry.

Defines : IdentifyHub — a thin container that stacks the existing IdentifyScreen
          (Run) and IdentifyResultsScreen (Results) behind a standard
          ``QTabWidget`` (document mode, styled by the theme's QTabBar block),
          so the two formerly-separate sidebar entries collapse into a single
          "Identify" one. The hub owns no logic of its own: it relays the
          wizard's busy/progress signals to the shell and forwards navigation
          payloads to the right child.
Used by : gui.views.shell (registered as the single "identify" screen).
Uses    : PySide6 (QTabWidget), gui.navigation, gui.views.screens_identify (IdentifyScreen),
          gui.views.screen_identify_results (IdentifyResultsScreen),
          gui.recent_store, gui.settings_store.

WHY relay busyChanged/progressChanged: the shell hooks a screen's own signals
(see OperationScreen) to reflect a running op in its chrome. Because the wizard now
sits inside the hub, the shell sees only the hub — so the hub must forward the
child's signals under its own name for the wizard's progress to still reach it.
The same argument applies to ``is_busy()`` / ``request_cancel()``: the shutdown
path questions the screens in the shell's stack, and the hub is what it finds
there.
"""

from __future__ import annotations


from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QTabWidget, QVBoxLayout, QWidget

from gui.navigation import Navigate, Payload
from gui.recent_store import RecentStore
from gui.settings_store import SettingsStore
from gui.views.screen_identify_results import IdentifyResultsScreen
from gui.views.screens_identify import IdentifyScreen

# Tab ids in index order — the only place the id↔index mapping lives.
_TAB_IDS = ("run", "results")


class IdentifyHub(QWidget):
    """Container holding the Identify wizard and results viewer in a QTabWidget."""

    screen_id = "identify"

    # Re-exported so the shell's OperationScreen wiring finds the same signal
    # names on the hub as on a plain OperationScreen (busy/progress relay).
    busyChanged = Signal(bool)
    progressChanged = Signal(float, str)

    def __init__(self, settings: SettingsStore, recents: RecentStore) -> None:
        super().__init__()
        self._run = IdentifyScreen(settings, recents)
        self._results = IdentifyResultsScreen(settings, recents)

        # Forward the wizard's signals under the hub's own name so the shell (which
        # only sees the hub) still reflects the run's progress/busy state.
        self._run.busyChanged.connect(self.busyChanged)
        self._run.progressChanged.connect(self.progressChanged)

        # Document mode drops the pane frame so the tabs read as a flat,
        # in-screen switcher (styled by the theme's QTabBar block).
        self._tabs = QTabWidget()
        self._tabs.setDocumentMode(True)
        # Match the Exploit tabs: no elision, no stretch, no base rule.
        tab_bar = self._tabs.tabBar()
        tab_bar.setElideMode(Qt.TextElideMode.ElideNone)
        tab_bar.setExpanding(False)
        tab_bar.setDrawBase(False)
        self._tabs.addTab(self._run, "Run")
        self._tabs.addTab(self._results, "Results")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._tabs)

    # ── Navigation (the gui.navigation.Screen protocol) ───────────────────────────

    def bind_navigator(self, navigate: Navigate) -> None:
        """Give both child screens the shell's navigate callback.

        The shell binds only what its stack holds — the hub — so the hub forwards
        the callback to the children that actually navigate (the wizard's "View
        results" and the viewer's export). Called by the shell.
        """
        self._run.bind_navigator(navigate)
        self._results.bind_navigator(navigate)

    # ── Busy / cancellation relay ─────────────────────────────────────────────────

    def is_busy(self) -> bool:
        """True while the wizard is running (the results viewer never is).

        WHY the hub must answer this: the shell asks each screen in its stack,
        and the hub is what the stack holds. Before this existed the shutdown
        path looked for a ``_thread`` attribute, which a plain ``QWidget`` like
        this one does not have — so a running identify was silently reported as
        idle and torn down mid-run on close.
        """
        return bool(self._run.is_busy())

    def request_cancel(self) -> bool:
        """Ask the wizard to abort; True if a request was actually made."""
        return bool(self._run.request_cancel())

    # ── Tab access ────────────────────────────────────────────────────────────────

    def set_tab(self, tab_id: str) -> None:
        if tab_id in _TAB_IDS:
            self._tabs.setCurrentIndex(_TAB_IDS.index(tab_id))

    def current_tab(self) -> str:
        return _TAB_IDS[self._tabs.currentIndex()]

    # ── Receive (shell navigation) ────────────────────────────────────────────────

    def receive(self, payload: Payload) -> None:
        """Route a payload addressed to "identify" to the child that takes it.

        :class:`ShowIdentifyResults` lands on the Results tab with the database
        opened; anything else is a routing bug and is refused (the results
        viewer's own ``receive`` raises).
        """
        self.set_tab("results")
        self._results.receive(payload)
