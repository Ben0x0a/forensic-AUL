"""Unit tests for the KB signature writer (render_signature / write_signature).

Uses    : forensic_aul.ops.knowledge_base.writer, .models, .loader.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from forensic_aul.ops.knowledge_base.loader import KnowledgeBaseError, load_kb
from forensic_aul.ops.knowledge_base.models import Match, SignatureDraft
from forensic_aul.ops.knowledge_base.writer import render_signature, write_signature


def _kb_root(tmp_path):
    """An empty, otherwise-valid KB root (VERSION + empty signatures/)."""
    root = tmp_path / "kb"
    root.mkdir()
    (root / "VERSION").write_text("1.0.0\n", encoding="utf-8")
    (root / "signatures").mkdir()
    return root


_FULL_DRAFT = SignatureDraft(
    id="net.test_sig",
    action="User's device did a thing",
    match=Match(
        format_str="Foo %@",
        process="wifid",
        subsystem="com.apple.wifi",
        event_type="Log",
    ),
    description="Line one.\nLine two.",
    interpretation="It means X.",
    caveats="Doesn't always hold.",
    extract_regex=r"to (?P<ssid>\S+) with bssid (?P<bssid>[0-9a-fA-F:]{17})",
    extract_fields=(("bundle_id", r"(?P<bundle_id>[\w.\-]+)"),),
    references=("Ref one",),
    tags=("network", "wifi"),
    author="ben",
    created="2026-08-11",
    version="0.1.0",
    status="draft",
)


# ── Golden render ─────────────────────────────────────────────────────────────

def test_render_signature_golden_output():
    expected = (
        "signatures:\n"
        "  - id: net.test_sig\n"
        '    action: "User\'s device did a thing"\n'
        "    description: |-\n"
        "      Line one.\n"
        "      Line two.\n"
        '    interpretation: "It means X."\n'
        '    caveats: "Doesn\'t always hold."\n'
        "    match:\n"
        '      format_str: "Foo %@"\n'
        "      process: wifid\n"
        "      subsystem: com.apple.wifi\n"
        "      event_type: Log\n"
        "    extract-regex: 'to (?P<ssid>\\S+) with bssid (?P<bssid>[0-9a-fA-F:]{17})'\n"
        "    extract-fields:\n"
        "      bundle_id: '(?P<bundle_id>[\\w.\\-]+)'\n"
        "    references:\n"
        '      - "Ref one"\n'
        "    tags: [network, wifi]\n"
        '    author: "ben"\n'
        '    created: "2026-08-11"\n'
        '    version: "0.1.0"\n'
        "    status: draft\n"
    )
    assert render_signature(_FULL_DRAFT) == expected


def test_render_signature_omits_defaults():
    # status="validated" explicitly, so this draft matches the Signature schema
    # default in every field and every optional key is omitted.
    draft = SignatureDraft(
        id="sb.minimal",
        action="Minimal signature",
        match=Match(format_str="Hi %@"),
        status="validated",
    )
    rendered = render_signature(draft)
    assert rendered == (
        "signatures:\n"
        "  - id: sb.minimal\n"
        '    action: "Minimal signature"\n'
        "    match:\n"
        '      format_str: "Hi %@"\n'
    )
    # Defaults never appear: confidence/platform/status defaults, empty prose.
    omitted = ("confidence", "platform", "description", "status", "author", "created", "version")
    for token in omitted:
        assert token not in rendered


def test_render_signature_defaults_status_to_draft():
    # SignatureDraft's own default status ("draft") differs from Signature's
    # schema default ("validated") on purpose — see models.py — so an
    # otherwise-minimal draft still emits an explicit `status: draft` line.
    draft = SignatureDraft(
        id="sb.minimal", action="Minimal signature", match=Match(format_str="Hi %@")
    )
    assert "status: draft" in render_signature(draft)


# ── Round trip: render → write → load_kb ────────────────────────────────────

def test_write_signature_round_trips_all_fields(tmp_path):
    root = _kb_root(tmp_path)
    path = write_signature(root, _FULL_DRAFT)
    assert path == root / "signatures" / "net.test_sig.yaml"

    sig = load_kb(root).signatures[0]
    assert sig.id == _FULL_DRAFT.id
    assert sig.action == _FULL_DRAFT.action
    assert sig.description == _FULL_DRAFT.description
    assert sig.interpretation == _FULL_DRAFT.interpretation
    assert sig.caveats == _FULL_DRAFT.caveats
    assert sig.match.format_str == _FULL_DRAFT.match.format_str
    assert sig.match.process == _FULL_DRAFT.match.process
    assert sig.match.subsystem == _FULL_DRAFT.match.subsystem
    assert sig.match.event_type == _FULL_DRAFT.match.event_type
    assert sig.extract_regex == _FULL_DRAFT.extract_regex
    assert sig.extract_fields == _FULL_DRAFT.extract_fields
    assert sig.references == _FULL_DRAFT.references
    assert sig.tags == _FULL_DRAFT.tags
    assert sig.author == _FULL_DRAFT.author
    assert sig.created == _FULL_DRAFT.created
    assert sig.version == _FULL_DRAFT.version
    assert sig.status == _FULL_DRAFT.status


def test_write_signature_refuses_to_overwrite(tmp_path):
    root = _kb_root(tmp_path)
    write_signature(root, _FULL_DRAFT)
    with pytest.raises(KnowledgeBaseError, match="already exists"):
        write_signature(root, _FULL_DRAFT)


def test_write_signature_rolls_back_two_anchors(tmp_path):
    root = _kb_root(tmp_path)
    write_signature(root, _FULL_DRAFT)  # a valid signature already on disk
    bad = replace(
        _FULL_DRAFT,
        id="net.bad_two_anchors",
        match=replace(_FULL_DRAFT.match, dynamic=True, message_regex="x"),
    )
    with pytest.raises(KnowledgeBaseError):
        write_signature(root, bad)
    assert not (root / "signatures" / "net.bad_two_anchors.yaml").exists()
    # Rollback must not corrupt the rest of the KB — the earlier one still loads.
    kb = load_kb(root)
    assert [s.id for s in kb.signatures] == [_FULL_DRAFT.id]


def test_write_signature_rolls_back_uncompilable_regex(tmp_path):
    root = _kb_root(tmp_path)
    bad = replace(
        _FULL_DRAFT,
        id="net.bad_regex",
        extract_regex="(?P<ssid>[unterminated",
        extract_fields=(),
    )
    with pytest.raises(KnowledgeBaseError):
        write_signature(root, bad)
    assert not (root / "signatures" / "net.bad_regex.yaml").exists()


# ── Escaping ──────────────────────────────────────────────────────────────────

def test_render_escapes_single_quote_in_single_line_field(tmp_path):
    draft = replace(_FULL_DRAFT, id="sb.quote_case", description="It's a device event.")
    root = _kb_root(tmp_path)
    write_signature(root, draft)
    sig = load_kb(root).signatures[0]
    assert sig.description == "It's a device event."


def test_render_escapes_newline_in_field(tmp_path):
    draft = replace(
        _FULL_DRAFT,
        id="sb.newline_case",
        caveats="First caveat.\nSecond caveat.\nThird.",
    )
    root = _kb_root(tmp_path)
    write_signature(root, draft)
    sig = load_kb(root).signatures[0]
    assert sig.caveats == "First caveat.\nSecond caveat.\nThird."


def test_regex_with_backslashes_survives_byte_identical(tmp_path):
    pattern = r"(?P<path>[A-Za-z0-9_/\\.\-]+\.plist)"
    draft = replace(
        _FULL_DRAFT,
        id="sb.backslash_case",
        extract_regex=pattern,
        extract_fields=(),
    )
    root = _kb_root(tmp_path)
    write_signature(root, draft)
    sig = load_kb(root).signatures[0]
    assert sig.extract_regex == pattern


# ── Encoding ──────────────────────────────────────────────────────────────────

def test_written_file_is_utf8_sig_and_loads(tmp_path):
    root = _kb_root(tmp_path)
    path = write_signature(root, _FULL_DRAFT)
    raw = path.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")  # UTF-8 BOM
    # load_kb must round-trip the BOM-prefixed file without corrupting the
    # first key (yaml.safe_load handles a leading U+FEFF even though load_kb
    # decodes with plain "utf-8", not "utf-8-sig").
    kb = load_kb(root)
    assert kb.signatures[0].id == _FULL_DRAFT.id
