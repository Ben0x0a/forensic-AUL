"""Unit tests for gui.controllers.phrase_failure.

Pure-function tests — gui.controllers.__init__ has no PySide6 dependency, so
these run without a QApplication.

Covers review items G4/G7: a failure reaches the GUI as the exception OBJECT and
is phrased by its TYPE — no traceback parsing, no patching of the library's own
sentence — and anything unrecognised still shows its real message.
"""

from __future__ import annotations

from pathlib import Path

from forensic_aul import InvalidDatabaseError, OutputExistsError, SourceError
from gui.controllers import phrase_failure


def test_an_existing_output_gets_gui_advice_naming_the_file():
    exc = OutputExistsError("/case.sqlite already exists; set overwrite=True to replace it",
                            path=Path("/case.sqlite"))
    phrased = phrase_failure(exc)
    assert phrased.startswith("/case.sqlite already exists.")
    assert "Overwrite the output database if it exists" in phrased
    assert "overwrite=True" not in phrased, "Python-keyword advice must not reach the GUI"


def test_subclasses_are_phrased_by_their_family():
    assert phrase_failure(SourceError("Source does not exist: /tmp/x")) == \
        "Unsupported source — Source does not exist: /tmp/x"
    assert phrase_failure(InvalidDatabaseError("/x.db is not a SQLite database")).startswith(
        "Not a usable database — /x.db")
    assert phrase_failure(FileNotFoundError("/missing.db is not a file")) == \
        "File not found — /missing.db is not a file"


def test_an_unmapped_exception_shows_its_real_message():
    """Never hidden behind a vague label."""
    exc = RuntimeError("pymobiledevice3 could not enumerate any device")
    assert phrase_failure(exc) == "RuntimeError: pymobiledevice3 could not enumerate any device"
