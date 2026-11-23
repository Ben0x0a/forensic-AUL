"""Author a knowledge-base signature from a selected log row.

Defines : SignatureDialog — a modal form that turns one log row into a validated
          ``signatures/<id>.yaml`` file, with a live YAML preview and a "test
          against the rows on screen" check.
Used by : gui.views.screen_identify_results (a context-menu action on the diff
          table).
Uses    : PySide6, forensic_aul (SignatureDraft, Match — the data the form
          builds), gui.controllers.signature (preview, rules, test, write),
          gui.widgets.components.

WHY a dialog rather than an inline panel: authoring a rule is a bounded, modal
act with a commit point (a file is written), unlike the browsing the rest of the
screen supports. It is deliberately NOT a text editor over raw YAML — the fields
mirror the loader's schema, so a signature that cannot load cannot be built here.

WHY the anchor is ``dynamic`` + ``message_regex`` and not ``format_str``: an
identify database carries no format-string column (see ops/identify/diff.py), so
the invariant template simply is not available at this call site. The regex is
seeded from the row's message, escaped, so the starting point matches exactly one
line and the analyst widens it deliberately.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import date
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from forensic_aul import Match, SignatureDraft
from gui.controllers.signature import SignatureController, suggest_id
from gui.widgets.components import (
    ComboBox,
    Divider,
    eyebrow,
    ghost_button,
    help_label,
    mono_input,
    primary_button,
    style_combo,
)

_CONFIDENCE = ("low", "medium", "high")

# Row fields offered as optional match constraints, in the order they narrow best:
# process first (indexed and highly selective), then the subsystem/category pair.
_CONSTRAINTS = (
    ("process", "Process"),
    ("subsystem", "Subsystem"),
    ("category", "Category"),
    ("log_level", "Level"),
)


class SignatureDialog(QDialog):
    """Turn *row* into a knowledge-base signature file.

    *row* is the raw row mapping from the results table; *sample_rows* are the
    rows currently loaded in that table, used by the Test button to report how
    many the draft regex would match. *kb_dir* defaults to the shipped knowledge
    base.
    """

    def __init__(
        self,
        row: Mapping[str, Any],
        *,
        sample_rows: list[Mapping[str, Any]] | None = None,
        kb_dir: Path | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._row = row
        self._sample_rows = sample_rows or []
        self._ctrl = SignatureController(kb_dir)
        self._written: Path | None = None

        self.setWindowTitle("New signature")
        self.setMinimumWidth(760)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(10)

        body = QHBoxLayout()
        body.setSpacing(16)
        body.addLayout(self._build_form(), 3)
        body.addLayout(self._build_preview(), 2)
        layout.addLayout(body, 1)

        layout.addWidget(Divider())
        layout.addWidget(self._status_label())
        layout.addLayout(self._build_buttons())

        self._refresh_preview()

    # ── Form ──────────────────────────────────────────────────────────────────────

    def _build_form(self) -> QVBoxLayout:
        column = QVBoxLayout()
        column.setSpacing(8)
        column.addWidget(eyebrow("Identity"))

        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        form.setSpacing(6)

        self._id = mono_input("net.wifi_join")
        self._id.setText(suggest_id(self._row))
        self._action = QLineEdit()
        self._action.setPlaceholderText("Device joined a Wi-Fi network")
        self._description = QLineEdit()
        self._interpretation = QLineEdit()
        self._interpretation.setPlaceholderText("What an analyst may conclude from this line")
        self._caveats = QLineEdit()
        self._caveats.setPlaceholderText("When that conclusion does not hold")
        self._tags = QLineEdit()
        self._tags.setPlaceholderText("network, wifi")
        self._references = QLineEdit()
        self._references.setPlaceholderText("Observed on iOS 17.5; case notes…")
        self._author = QLineEdit()
        self._confidence = ComboBox()
        for value in _CONFIDENCE:
            self._confidence.addItem(value, value)
        self._confidence.setCurrentIndex(_CONFIDENCE.index("medium"))
        style_combo(self._confidence)

        form.addRow("Id", self._id)
        form.addRow("Action", self._action)
        form.addRow("Description", self._description)
        form.addRow("Interpretation", self._interpretation)
        form.addRow("Caveats", self._caveats)
        form.addRow("Confidence", self._confidence)
        form.addRow("Tags", self._tags)
        form.addRow("References", self._references)
        form.addRow("Author", self._author)
        column.addLayout(form)

        column.addWidget(eyebrow("Match"))
        column.addWidget(help_label(
            "Anchored on the message pattern: an identify database carries no "
            "format string. The regex starts escaped, matching this line exactly "
            "— widen it deliberately."
        ))
        self._regex = mono_input("")
        self._regex.setText(re.escape(str(self._row.get("message") or "")))
        column.addWidget(self._regex)

        self._constraints: dict[str, QCheckBox] = {}
        constraint_row = QHBoxLayout()
        constraint_row.setSpacing(10)
        for key, label in _CONSTRAINTS:
            value = self._row.get(key) or self._row.get(_ALIASES.get(key, key))
            box = QCheckBox(f"{label}: {value}" if value else label)
            box.setEnabled(bool(value))
            box.setChecked(bool(value) and key == "process")
            box.toggled.connect(self._refresh_preview)
            self._constraints[key] = box
            constraint_row.addWidget(box)
        constraint_row.addStretch(1)
        column.addLayout(constraint_row)
        column.addStretch(1)

        for field in (self._id, self._action, self._description, self._interpretation,
                      self._caveats, self._tags, self._references, self._author,
                      self._regex):
            field.textChanged.connect(self._refresh_preview)
        self._confidence.currentIndexChanged.connect(self._refresh_preview)
        return column

    def _build_preview(self) -> QVBoxLayout:
        column = QVBoxLayout()
        column.setSpacing(8)
        column.addWidget(eyebrow("YAML preview"))
        self._preview = QPlainTextEdit()
        self._preview.setReadOnly(True)
        self._preview.setProperty("mono", "true")
        column.addWidget(self._preview, 1)
        return column

    def _status_label(self) -> QLabel:
        self._status = help_label("")
        return self._status

    def _build_buttons(self) -> QHBoxLayout:
        row = QHBoxLayout()
        test = ghost_button("Test", "search")
        test.setToolTip("Count how many of the rows on screen this regex matches")
        test.clicked.connect(self._on_test)
        row.addWidget(test)
        row.addStretch(1)

        self._buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        save = primary_button("Save signature", "check")
        save.clicked.connect(self._on_save)
        self._buttons.addButton(save, QDialogButtonBox.ButtonRole.AcceptRole)
        self._buttons.rejected.connect(self.reject)
        row.addWidget(self._buttons)
        return row

    # ── Draft ─────────────────────────────────────────────────────────────────────

    def draft(self) -> SignatureDraft:
        """The current form state as a :class:`SignatureDraft`."""
        constraints = {
            key: str(self._row.get(key) or self._row.get(_ALIASES.get(key, key)) or "")
            for key, box in self._constraints.items()
            if box.isChecked()
        }
        return SignatureDraft(
            id=self._id.text().strip(),
            action=self._action.text().strip(),
            description=self._description.text().strip(),
            interpretation=self._interpretation.text().strip(),
            caveats=self._caveats.text().strip(),
            confidence=self._confidence.currentData() or "medium",
            tags=_split(self._tags.text()),
            references=_split(self._references.text(), sep=";"),
            author=self._author.text().strip(),
            created=date.today().isoformat(),
            match=Match(
                dynamic=True,
                message_regex=self._regex.text() or None,
                process=constraints.get("process") or None,
                subsystem=constraints.get("subsystem") or None,
                category=constraints.get("category") or None,
                log_level=constraints.get("log_level") or None,
            ),
        )

    def _refresh_preview(self, *_args: Any) -> None:
        self._preview.setPlainText(self._ctrl.preview(self.draft()))
        self._validate()

    def _validate(self) -> None:
        """Report the first problem that would stop a save, before it is attempted."""
        problems = self._ctrl.problems(
            sig_id=self._id.text().strip(), action=self._action.text().strip(),
            regex=self._regex.text().strip() and self._regex.text(),
        )
        self._status.setText(problems[0] if problems else "Ready to save.")
        self._save_enabled(not problems)

    def _save_enabled(self, enabled: bool) -> None:
        for button in self._buttons.buttons():
            if self._buttons.buttonRole(button) == QDialogButtonBox.ButtonRole.AcceptRole:
                button.setEnabled(enabled)

    # ── Actions ───────────────────────────────────────────────────────────────────

    def _on_test(self) -> None:
        """Count matches among the rows currently on screen (see the controller)."""
        self._status.setText(self._ctrl.test(self._regex.text(), self._sample_rows))

    def _on_save(self) -> None:
        written, why = self._ctrl.save(self.draft())
        if written is None:
            # Keep the dialog open: the draft is still in the form and the message
            # names what to change.
            self._status.setText(why)
            return
        self._written = written
        self.accept()

    def written_path(self) -> Path | None:
        """The file written, once the dialog has been accepted."""
        return self._written


# Row keys that differ between the identify and exploit table shapes. The
# identify database names the column `log_level`; the exploit row dict uses
# `level`. Consumed by: _build_form, draft.
_ALIASES = {"log_level": "level"}


def _split(text: str, *, sep: str = ",") -> tuple[str, ...]:
    return tuple(part.strip() for part in text.split(sep) if part.strip())


__all__ = ["SignatureDialog"]
