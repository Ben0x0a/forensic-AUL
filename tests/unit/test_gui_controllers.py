"""Unit tests for gui.controllers (last_line / phrase_failure).

Pure-function tests — gui.controllers.__init__ has no PySide6 dependency, so
these run without a QApplication.

Covers review item G7: failures previously showed the traceback's last line
verbatim, including API-caller advice ("pass overwrite=True to replace it")
aimed at a Python caller, not someone looking at a checkbox. phrase_failure()
rewrites a handful of known exception types for the GUI and — critically —
still shows the real message, unmodified, for anything it does not recognise.
"""

from __future__ import annotations

from gui.controllers import last_line, phrase_failure


def _tb(exc_line: str) -> str:
    """Build a traceback-shaped string whose last line is *exc_line*."""
    return f'Traceback (most recent call last):\n  File "x.py", line 1, in <module>\n{exc_line}\n'


def test_last_line_empty_on_blank_traceback():
    assert last_line("") == ""
    assert last_line("   \n  ") == ""


def test_last_line_returns_final_line():
    assert last_line(_tb("ValueError: boom")) == "ValueError: boom"


def test_phrase_failure_empty_traceback():
    assert phrase_failure("") == ""


def test_phrase_failure_rewrites_file_exists_error_overwrite_advice():
    tb = _tb(
        "FileExistsError: /case.sqlite already exists; pass overwrite=True to "
        "replace it (extracting into an existing database would merge two acquisitions)"
    )
    phrased = phrase_failure(tb)
    assert "pass overwrite=True" not in phrased, "Python-kwarg advice must not reach the GUI"
    assert 'tick "Overwrite the output database if it exists"' in phrased
    assert "/case.sqlite already exists" in phrased, "the real message must survive the rewrite"
    assert "merge two acquisitions" in phrased, "the WHY explanation must not be dropped"


def test_phrase_failure_strips_module_prefix_for_custom_exceptions():
    """forensic_aul.errors.SourceError must match on its bare class name."""
    tb = _tb("forensic_aul.errors.SourceError: Source does not exist: /tmp/x")
    assert phrase_failure(tb) == "Unsupported source — Source does not exist: /tmp/x"


def test_phrase_failure_invalid_database_error():
    tb = _tb(
        "forensic_aul.errors.InvalidDatabaseError: /x.db is not a SQLite "
        "database: file is not a database"
    )
    phrased = phrase_failure(tb)
    assert phrased.startswith("Not a usable database — ")
    assert "/x.db is not a SQLite database" in phrased


def test_phrase_failure_file_not_found_error():
    tb = _tb("FileNotFoundError: /missing.db is not a file")
    assert phrase_failure(tb) == "File not found — /missing.db is not a file"


def test_phrase_failure_unmapped_exception_shows_real_message_verbatim():
    """An exception with no phrasing entry must never be hidden behind a vague label."""
    tb = _tb("RuntimeError: pymobiledevice3 could not enumerate any device")
    assert phrase_failure(tb) == "RuntimeError: pymobiledevice3 could not enumerate any device"
