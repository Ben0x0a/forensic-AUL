"""Identify hub: the wizard + results viewer under one sidebar entry.

Defines : IdentifyHub — a thin container that stacks the existing IdentifyScreen
          (Run) and IdentifyResultsScreen (Results) behind a standard
          ``QTabWidget`` (document mode, styled by the theme's QTabBar block),
          so the two formerly-separate sidebar entries collapse into a single
          "Identify" one. The hub owns no logic of its own: it relays the
          wizard's busy/progress signals to the shell and forwards navigation
          prefill to the right child.
Used by : gui.views.shell (registered as the single "identify" screen).
Uses    : PySide6 (QTabWidget), gui.views.screens_identify (IdentifyScreen),
          gui.views.screen_identify_results (IdentifyResultsScreen),
          gui.recent_store, gui.settings_store.

WHY relay busyChanged/progressChanged: the shell hooks a screen's own signals
(see OperationScreen) to reflect a running op in its chrome. Because the wizard now
sits inside the hub, the shell sees only the hub — so the hub must forward the
child's signals under its own name for the wizard's progress to still reach it.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QTabWidget, QVBoxLayout, QWidget

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

    # ── Navigation glue (the shell sets .navigate on each child) ──────────────────

    def set_navigate(self, navigate: Any) -> None:
        """Give both child screens the shell's navigate callback.

        The shell's ``_add_screen`` only sets ``.navigate`` on the hub, so the hub
        propagates it to the children that actually navigate (the wizard's
        "View results" and the viewer's export). Called by the shell.
        """
        self._run.navigate = navigate
        self._results.navigate = navigate

    # ── Tab access ────────────────────────────────────────────────────────────────

    def set_tab(self, tab_id: str) -> None:
        if tab_id in _TAB_IDS:
            self._tabs.setCurrentIndex(_TAB_IDS.index(tab_id))

    def current_tab(self) -> str:
        return _TAB_IDS[self._tabs.currentIndex()]

    # ── Prefill (shell navigation) ────────────────────────────────────────────────

    def prefill(self, data: dict[str, Any]) -> None:
        """Switch to the tab named in *data* and forward any payload to it.

        ``{"tab": "results", "db": …}`` lands on the results viewer with the DB
        opened; ``{"tab": "run"}`` (or an absent tab) shows the wizard. Mirrors the
        shell's other prefill hooks (see shell.set_current).
        """
        tab = data.get("tab", "run")
        self.set_tab(tab if tab in _TAB_IDS else "run")
        if tab == "results":
            self._results.prefill(data)
