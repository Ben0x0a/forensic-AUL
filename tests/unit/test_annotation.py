"""Unit tests for KB extract_regex → extracted_values (loader + matcher)."""

from __future__ import annotations

import sqlite3

import pytest

from forensic_aul.ops.knowledge_base.lint import lint_labels, signature_labels
from forensic_aul.ops.knowledge_base.loader import KnowledgeBaseError, load_kb
from forensic_aul.ops.annotation.matcher import annotate_connection
from forensic_aul.engine.database.schema import apply_pragmas, init_schema


def _write_kb(root, signature_yaml: str, labels_yaml: str | None = None) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "VERSION").write_text("1.0.0\n", encoding="utf-8")
    sigs = root / "signatures"
    sigs.mkdir()
    (sigs / "s.yaml").write_text("signatures:\n" + signature_yaml, encoding="utf-8")
    if labels_yaml is not None:
        (root / "labels.yaml").write_text(labels_yaml, encoding="utf-8")


_WIFI_SIG = """\
  - id: net.wifi
    action: "Wi-Fi association"
    match:
      format_str: "Associated to %@ with bssid %@"
      process: wifid
    extract-regex: 'to (?P<ssid>\\S+) with bssid (?P<bssid>[0-9a-fA-F:]{17})'
    tags: [wifi]
"""


def _db_with_match(path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    apply_pragmas(conn)
    init_schema(conn)
    conn.execute("INSERT INTO processes(id, name) VALUES (1, 'wifid')")
    conn.execute("INSERT INTO format_strs(id, value) VALUES (1, 'Associated to %@ with bssid %@')")
    conn.execute(
        "INSERT INTO logs(id, timestamp_unix_ns, timestamp_mach, "
        "message, process_id, format_str_id) VALUES (1, ?, ?, ?, 1, 1)",
        (1_705_320_001_000_000_000, 1000,
         "Associated to HomeNet with bssid aa:bb:cc:dd:ee:ff"),
    )
    conn.commit()
    return conn


# ── Loader validation ─────────────────────────────────────────────────────────

def test_loader_accepts_named_group_regex(tmp_path):
    _write_kb(tmp_path, _WIFI_SIG)
    kb = load_kb(tmp_path)
    sig = kb.signatures[0]
    assert sig.extract_regex is not None
    assert sig._compiled_extract_regex is not None
    assert set(sig._compiled_extract_regex.groupindex) == {"ssid", "bssid"}


def test_loader_rejects_regex_without_named_group(tmp_path):
    bad = """\
  - id: net.wifi
    action: "x"
    match:
      format_str: "Associated to %@"
      process: wifid
    extract-regex: 'to (\\S+)'
"""
    _write_kb(tmp_path, bad)
    with pytest.raises(KnowledgeBaseError, match="named group"):
        load_kb(tmp_path)


def test_loader_rejects_invalid_regex(tmp_path):
    bad = """\
  - id: net.wifi
    action: "x"
    match:
      format_str: "Associated to %@"
      process: wifid
    extract-regex: '(?P<ssid>[unterminated'
"""
    _write_kb(tmp_path, bad)
    with pytest.raises(KnowledgeBaseError):
        load_kb(tmp_path)


# ── Matcher → extracted_values ────────────────────────────────────────────────

def test_extract_regex_populates_extracted_values(tmp_path):
    kb_root = tmp_path / "kb"
    _write_kb(kb_root, _WIFI_SIG)
    kb = load_kb(kb_root)

    conn = _db_with_match(tmp_path / "case.db")
    try:
        result = annotate_connection(conn, kb)
        assert result.counts == {"net.wifi": 1}

        rows = dict(conn.execute(
            "SELECT label, value FROM extracted_values ev "
            "JOIN log_annotations la ON la.id = ev.log_annotation_id"
        ).fetchall())
    finally:
        conn.close()

    assert rows == {"ssid": "HomeNet", "bssid": "aa:bb:cc:dd:ee:ff"}


def test_no_extraction_when_regex_absent(tmp_path):
    kb_root = tmp_path / "kb"
    _write_kb(kb_root, """\
  - id: net.wifi
    action: "Wi-Fi association"
    match:
      format_str: "Associated to %@ with bssid %@"
      process: wifid
    tags: [wifi]
""")
    kb = load_kb(kb_root)
    conn = _db_with_match(tmp_path / "case.db")
    try:
        annotate_connection(conn, kb)
        assert conn.execute("SELECT COUNT(*) FROM log_annotations").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM extracted_values").fetchone()[0] == 0
    finally:
        conn.close()


# ── Label vocabulary + linting ────────────────────────────────────────────────

_LABELS = "labels:\n  ssid: 'Wi-Fi name'\n  bssid: 'AP MAC'\n  bundle_id: 'App id'\n"


def test_signature_labels_lists_regex_groups_and_fields(tmp_path):
    _write_kb(tmp_path, _WIFI_SIG)
    sig = load_kb(tmp_path).signatures[0]
    assert signature_labels(sig) == ["ssid", "bssid"]


def test_load_kb_reads_vocabulary(tmp_path):
    _write_kb(tmp_path, _WIFI_SIG, labels_yaml=_LABELS)
    kb = load_kb(tmp_path)
    assert kb.allowed_label_names() == {"ssid", "bssid", "bundle_id"}


def test_lint_no_warnings_when_labels_known(tmp_path):
    _write_kb(tmp_path, _WIFI_SIG, labels_yaml=_LABELS)
    assert lint_labels(load_kb(tmp_path)) == []


def test_lint_skipped_without_vocabulary(tmp_path):
    # No labels.yaml → vocabulary opt-in → no warnings even for novel labels.
    _write_kb(tmp_path, _WIFI_SIG)
    assert lint_labels(load_kb(tmp_path)) == []


def test_lint_warns_and_suggests_close_label(tmp_path):
    # 'SSID' (wrong case) is unknown but close to the allowed 'ssid'.
    sig = """\
  - id: net.wifi
    action: "x"
    match:
      format_str: "Associated to %@"
      process: wifid
    extract-regex: 'to (?P<SSID>\\S+)'
"""
    _write_kb(tmp_path, sig, labels_yaml=_LABELS)
    warnings = lint_labels(load_kb(tmp_path))
    assert len(warnings) == 1
    assert warnings[0].label == "SSID"
    assert warnings[0].suggestion == "ssid"
    assert "did you mean 'ssid'" in warnings[0].message()


def test_lint_warns_without_suggestion_when_nothing_close(tmp_path):
    sig = """\
  - id: net.wifi
    action: "x"
    match:
      format_str: "Associated to %@"
      process: wifid
    extract-regex: 'to (?P<totally_unrelated>\\S+)'
"""
    _write_kb(tmp_path, sig, labels_yaml=_LABELS)
    warnings = lint_labels(load_kb(tmp_path))
    assert len(warnings) == 1 and warnings[0].suggestion is None
