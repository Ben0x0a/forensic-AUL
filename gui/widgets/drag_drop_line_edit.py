"""Drag-and-drop enabled QLineEdit.

Defines : DragDropLineEdit, a QLineEdit that accepts a single file/folder drop
          and sets its text to the dropped local path.
Used by : the screen .ui files (promoted on path fields) and gui.views.MainWindow
          (registers it on the QUiLoader so promoted widgets resolve).
Uses    : PySide6 only.

WHY: Qt has native, cross-platform drag-and-drop. The default QLineEdit drop
inserts the raw URI text, which is wrong for a path field — so we override the
drag/drop events to convert the first URL to a local path and reject non-file
URLs (http://, etc.) that no downstream code can resolve.
"""

from __future__ import annotations

from PySide6.QtGui import QDragEnterEvent, QDropEvent
from PySide6.QtWidgets import QLineEdit, QWidget


class DragDropLineEdit(QLineEdit):
    """QLineEdit that accepts a single file/folder drop and sets its path."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event: QDragEnterEvent) -> None:
        # Qt needs both dragEnter and dragMove to accept, for hover feedback.
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event: QDropEvent) -> None:
        urls = event.mimeData().urls()
        if not urls:
            event.ignore()
            return
        local = urls[0].toLocalFile()
        if not local:
            # Non-file URL — refuse rather than insert an unresolvable URI.
            event.ignore()
            return
        self.setText(local)
        event.acceptProposedAction()
