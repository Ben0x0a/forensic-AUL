"""A path-input widget: drag-drop line edit + a Browse button.

Defines : PathPicker, a small composite for choosing a file or directory (open
          or save). Wraps DragDropLineEdit so a user can drag a path in or click
          Browse. Pure view widget — no business logic.
Used by : gui.views.* (every screen with a path field).
Uses    : PySide6, gui.widgets.drag_drop_line_edit.
"""

from __future__ import annotations

from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QPushButton, QWidget

from gui.widgets.drag_drop_line_edit import DragDropLineEdit


class PathPicker(QWidget):
    """Line edit (drag-drop aware) + Browse button.

    *mode* selects the dialog: ``"file"`` (open file), ``"dir"`` (open folder),
    or ``"save"`` (save file). *name_filter* is the Qt filter string for file modes.
    """

    def __init__(
        self,
        mode: str = "file",
        *,
        placeholder: str = "",
        caption: str = "Choose…",
        name_filter: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        if mode not in ("file", "dir", "save"):
            raise ValueError(f"invalid PathPicker mode: {mode!r}")
        self._mode = mode
        self._caption = caption
        self._filter = name_filter

        self.edit = DragDropLineEdit()
        if placeholder:
            self.edit.setPlaceholderText(placeholder)
        browse = QPushButton("Browse…")
        browse.setAutoDefault(False)
        browse.clicked.connect(self._browse)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.edit, 1)
        layout.addWidget(browse)

    def _browse(self) -> None:
        if self._mode == "dir":
            path = QFileDialog.getExistingDirectory(self, self._caption, self.path())
        elif self._mode == "save":
            path, _ = QFileDialog.getSaveFileName(self, self._caption, self.path(), self._filter)
        else:
            path, _ = QFileDialog.getOpenFileName(self, self._caption, self.path(), self._filter)
        if path:
            self.edit.setText(path)

    def path(self) -> str:
        return self.edit.text().strip()

    def set_path(self, value: str) -> None:
        self.edit.setText(value)
