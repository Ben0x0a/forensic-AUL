"""Unit tests for KB extract_regex → extracted_values (loader + matcher)."""

from __future__ import annotations

import sqlite3

import pytest

from forensic_aul.ops.knowledge_base.lint import lint_labels, signature_labels
from forensic_aul.ops.knowledge_base.loader import KnowledgeBaseError, load_kb
from forensic_aul.ops.annotation.matcher import (
    annotate_connection,
    annotation_state,
    clear_annotations,
)
from forensic_aul.ops.summary.cache import load_summary, store_summary
from forensic_aul.ops.summary.summary import summarise_connection
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


# ── Schema additions: interpretation/caveats/provenance/status ────────────────

def test_new_fields_default(tmp_path):
    _write_kb(tmp_path, _WIFI_SIG)
    sig = load_kb(tmp_path).signatures[0]
    assert sig.interpretation == ""
    assert sig.caveats == ""
    assert sig.author == ""
    assert sig.created == ""
    assert sig.version == ""
    assert sig.status == "validated"
    assert sig.match.event_type is None
    assert sig.match.library is None


def test_loader_accepts_new_fields(tmp_path):
    sig_yaml = """\
  - id: net.wifi
    action: "Wi-Fi association"
    interpretation: "The device joined this network."
    caveats: "Also fires on captive-portal probes."
    author: "analyst"
    created: "2026-01-15"
    version: "1.0.0"
    status: draft
    match:
      format_str: "Associated to %@ with bssid %@"
      process: wifid
      event_type: Log
      library: "/usr/lib/libnetwork.dylib"
"""
    _write_kb(tmp_path, sig_yaml)
    sig = load_kb(tmp_path).signatures[0]
    assert sig.interpretation == "The device joined this network."
    assert sig.caveats == "Also fires on captive-portal probes."
    assert sig.author == "analyst"
    assert sig.created == "2026-01-15"
    assert sig.version == "1.0.0"
    assert sig.status == "draft"
    assert sig.match.event_type == "Log"
    assert sig.match.library == "/usr/lib/libnetwork.dylib"


def test_loader_rejects_unknown_status(tmp_path):
    bad = """\
  - id: net.wifi
    action: "x"
    status: experimental
    match:
      format_str: "Associated to %@"
      process: wifid
"""
    _write_kb(tmp_path, bad)
    with pytest.raises(KnowledgeBaseError, match="status"):
        load_kb(tmp_path)


def test_loader_rejects_malformed_created_date(tmp_path):
    bad = """\
  - id: net.wifi
    action: "x"
    created: "15 Jan 2026"
    match:
      format_str: "Associated to %@"
      process: wifid
"""
    _write_kb(tmp_path, bad)
    with pytest.raises(KnowledgeBaseError, match="created"):
        load_kb(tmp_path)


def test_loader_rejects_unknown_event_type(tmp_path):
    bad = """\
  - id: net.wifi
    action: "x"
    match:
      format_str: "Associated to %@"
      process: wifid
      event_type: Bogus
"""
    _write_kb(tmp_path, bad)
    with pytest.raises(KnowledgeBaseError, match="event_type"):
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


# ── Summary cache refresh ─────────────────────────────────────────────────────

def _db_with_metadata(path) -> sqlite3.Connection:
    """A matchable database that also carries case_metadata, so it can be summarised."""
    conn = _db_with_match(path)
    conn.execute(
        "INSERT INTO case_metadata(case_number, acquisition_timestamp, tool_version) "
        "VALUES ('C1', '2024-01-15T00:00:00Z', '0.1.0')"
    )
    conn.commit()
    return conn


def test_annotate_refreshes_summary_cache(tmp_path):
    """Annotating rewrites the cached statistics so annotated_count is not stale."""
    _write_kb(tmp_path / "kb", _WIFI_SIG)
    kb = load_kb(tmp_path / "kb")
    conn = _db_with_metadata(tmp_path / "a.db")

    # Cache the pre-annotation state, as extract would have done.
    before = summarise_connection(conn, top=5, buckets=10)
    store_summary(conn, before, top=5, buckets=10)
    assert load_summary(conn).annotated_count == 0

    annotate_connection(conn, kb)

    after = load_summary(conn)
    assert after is not None
    assert after.annotated_count == 1
    assert after.signature_count == 1
    conn.close()


def test_annotate_survives_unsummarisable_database(tmp_path):
    """No case_metadata → the refresh is skipped, not fatal, and leaves no stale cache."""
    _write_kb(tmp_path / "kb", _WIFI_SIG)
    kb = load_kb(tmp_path / "kb")
    conn = _db_with_match(tmp_path / "a.db")  # deliberately no case_metadata row

    result = annotate_connection(conn, kb)

    assert result.total_matches == 1
    assert load_summary(conn) is None
    conn.close()


# ── Applicability gating (review item L6) ─────────────────────────────────────

_GATED_SIG = """\
  - id: net.wifi
    action: "Wi-Fi association"
    ios_min: "16.0"
    ios_max: "17.9"
    match:
      format_str: "Associated to %@ with bssid %@"
      process: wifid
"""


def _db_with_ios(path, version: str | None):
    conn = _db_with_match(path)
    conn.execute(
        "INSERT INTO case_metadata(case_number, ios_version, acquisition_timestamp, "
        "tool_version) VALUES ('C1', ?, '2024-01-15T00:00:00Z', '0.1.0')",
        (version,),
    )
    conn.commit()
    return conn


@pytest.mark.parametrize("version,expected", [
    ("17.5.1", 1),   # inside the declared range
    ("16.0", 1),     # lower bound is inclusive
    ("15.7", 0),     # below ios_min
    ("18.0", 0),     # above ios_max
])
def test_ios_version_gate(tmp_path, version, expected):
    _write_kb(tmp_path / "kb", _GATED_SIG)
    kb = load_kb(tmp_path / "kb")
    conn = _db_with_ios(tmp_path / f"a{version}.db", version)
    assert annotate_connection(conn, kb).total_matches == expected
    conn.close()


def test_unknown_ios_version_applies_every_signature(tmp_path):
    """An absent version must not silently suppress annotations — see the WHY."""
    _write_kb(tmp_path / "kb", _GATED_SIG)
    kb = load_kb(tmp_path / "kb")
    conn = _db_with_ios(tmp_path / "unknown.db", None)
    assert annotate_connection(conn, kb).total_matches == 1
    conn.close()


def test_other_platform_is_skipped(tmp_path):
    sig = _GATED_SIG.replace('    ios_min: "16.0"', '    platform: macos\n    ios_min: "16.0"')
    _write_kb(tmp_path / "kb", sig)
    kb = load_kb(tmp_path / "kb")
    conn = _db_with_ios(tmp_path / "mac.db", "17.5")
    assert annotate_connection(conn, kb).total_matches == 0
    conn.close()


# ── Self-describing annotations ───────────────────────────────────────────────

def test_kb_signatures_carries_the_whole_rule(tmp_path):
    """The database must explain a flag without the knowledge base on disk."""
    _write_kb(tmp_path / "kb", _WIFI_SIG)
    kb = load_kb(tmp_path / "kb")
    conn = _db_with_metadata(tmp_path / "a.db")
    annotate_connection(conn, kb)

    row = conn.execute(
        "SELECT match_json, extract_json, platform, status, tags "
        "FROM kb_signatures WHERE signature_id = 'net.wifi'"
    ).fetchone()
    import json as _json
    match = _json.loads(row[0])
    assert match["format_str"] == "Associated to %@ with bssid %@"
    assert match["process"] == "wifid"
    assert "extract_regex" in _json.loads(row[1])
    assert row[2] == "ios"
    assert row[3] == "validated"
    assert _json.loads(row[4]) == ["wifi"]
    conn.close()


# ── clear_annotations ─────────────────────────────────────────────────────────

def test_clear_annotations_empties_all_three_tables(tmp_path):
    _write_kb(tmp_path / "kb", _WIFI_SIG)
    kb = load_kb(tmp_path / "kb")
    conn = _db_with_metadata(tmp_path / "a.db")
    annotate_connection(conn, kb)
    assert annotation_state(conn)["annotated"] == 1

    removed = clear_annotations(conn)
    assert removed == 1
    for table in ("extracted_values", "log_annotations", "kb_signatures"):
        assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
    # The cached statistics follow the data rather than reporting the old counts.
    assert load_summary(conn).annotated_count == 0
    conn.close()


def test_clear_annotations_on_a_never_annotated_db(tmp_path):
    conn = _db_with_metadata(tmp_path / "clean.db")
    assert clear_annotations(conn) == 0
    assert annotation_state(conn) == {
        "annotated": 0, "signatures": 0, "kb_versions": [], "applied_at": [],
    }
    conn.close()


def test_annotate_twice_duplicates_and_clearing_fixes_it(tmp_path):
    """The append-only behaviour is real — this is why the GUI refuses a re-run."""
    _write_kb(tmp_path / "kb", _WIFI_SIG)
    kb = load_kb(tmp_path / "kb")
    conn = _db_with_metadata(tmp_path / "a.db")
    annotate_connection(conn, kb)
    annotate_connection(conn, kb)

    state = annotation_state(conn)
    assert state["annotated"] == 1        # COUNT(DISTINCT log_id) hides it…
    assert state["signatures"] == 2       # …but the signature rows doubled
    assert conn.execute("SELECT COUNT(*) FROM log_annotations").fetchone()[0] == 2

    clear_annotations(conn)
    annotate_connection(conn, kb)
    assert annotation_state(conn)["signatures"] == 1
    conn.close()
