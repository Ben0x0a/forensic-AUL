"""The ``test`` self-check pipeline: acquire / generate-reference / extract / compare.

This is QA tooling, not a user-facing operation — it orchestrates the extract
pipeline, Apple's ``log show``/``log collect`` CLIs, and the comparator to prove
our output matches Apple's ground truth. It is non-interactive: the argument
*shape* selects the mode, and everything else runs to completion. The CLI
handler (``launcher/cmds/test_cmd.py``) only parses arguments and calls
:func:`run`.

Source forms (auto-detected by file shape):

  test                                 # mac: list devices, refuse otherwise
  test --from-device [NAME_OR_UDID]    # mac: collect → show → extract → diff
  test <logarchive> [ref.ndjson]       # extract → diff (ref auto-made on mac)
  test <db.sqlite>  <ref.ndjson>       # diff only
  test <db.sqlite>  --regen-ref <logarchive>   # mac: re-make ref, then diff
"""

from __future__ import annotations

import argparse
import logging
import shlex
import tempfile
from pathlib import Path

log = logging.getLogger(__name__)


# ── Source classification ─────────────────────────────────────────────────────

def _is_logarchive(path: Path) -> bool:
    """Return True if *path* looks like a .logarchive directory."""
    if not path.is_dir():
        return False
    # Canonical indicator: a 'Persist' or 'timesync' sub-directory
    return (path / "Persist").is_dir() or (path / "timesync").is_dir()


def _is_sqlite(path: Path) -> bool:
    return path.is_file() and path.suffix.lower() in {".db", ".sqlite", ".sqlite3"}


# ── Resource manager for the ndjson + DB temp paths ───────────────────────────

class _Resources:
    """Owns temp dirs and tracks which paths are temporary.

    Keeps the cleanup logic in one place so the dispatcher does not have to
    juggle four optional ``TemporaryDirectory`` handles itself.
    """

    def __init__(self) -> None:
        self._dirs: list[tempfile.TemporaryDirectory] = []
        self._tmp_paths: set[Path] = set()

    def tempdir(self, *, prefix: str) -> Path:
        td = tempfile.TemporaryDirectory(prefix=prefix)
        self._dirs.append(td)
        return Path(td.name)

    def mark_temp(self, path: Path) -> None:
        self._tmp_paths.add(path)

    def cleanup(self, *, keep_paths: set[Path]) -> None:
        """Clean up every temp dir whose contents are not in *keep_paths*.

        Tempdirs that hold a "kept" file are left on disk so the user can
        inspect them later — the file is inside the dir.
        """
        for td in self._dirs:
            td_path = Path(td.name)
            if any(p == td_path or td_path in p.parents for p in keep_paths):
                continue
            td.cleanup()


# ── Public entry point ────────────────────────────────────────────────────────

def run(args: argparse.Namespace) -> int:
    """Run the self-check pipeline for the parsed CLI *args*."""
    resources = _Resources()
    keep_paths: set[Path] = set()

    try:
        return _dispatch(args, resources, keep_paths)
    finally:
        resources.cleanup(keep_paths=keep_paths)


def _dispatch(
    args: argparse.Namespace,
    resources: _Resources,
    keep_paths: set[Path],
) -> int:
    """Decide what to acquire/generate based on argument shape."""
    from forensic_aul.testing.platform import is_macos

    # Mode "no args": list devices on macOS, otherwise help.
    if args.source is None and args.from_device is None and args.regen_ref is None:
        return _print_devices_or_help()

    # Mode 2: --from-device (acquire fresh logarchive from a phone, then full pipeline)
    if args.from_device is not None:
        if not is_macos():
            log.error("error: --from-device requires macOS (Apple `log collect`).")
            return 1
        logarchive = _collect_from_device(args.from_device or None, resources)
        ref_path = _make_reference(logarchive, args, resources, keep_paths)
        db_path = _extract_logarchive(logarchive, args, resources, keep_paths)
        return _run_compare(db_path, ref_path, args)

    # Beyond this point, SOURCE is required.
    if args.source is None:
        log.error("error: SOURCE is required (or use --from-device).")
        return 1

    source = args.source

    # Mode 4: existing DB + --regen-ref → mac-only path
    if _is_sqlite(source) and args.regen_ref is not None:
        ref_path = _make_reference(args.regen_ref, args, resources, keep_paths)
        return _run_compare(source, ref_path, args)

    # Mode 3a: logarchive + explicit ref
    if _is_logarchive(source) and args.reference is not None:
        if not args.reference.is_file():
            log.error(f"error: reference ndjson not found: {args.reference}")
            return 1
        db_path = _extract_logarchive(source, args, resources, keep_paths)
        return _run_compare(db_path, args.reference, args)

    # Mode 3b: DB + explicit ref
    if _is_sqlite(source) and args.reference is not None:
        if not args.reference.is_file():
            log.error(f"error: reference ndjson not found: {args.reference}")
            return 1
        return _run_compare(source, args.reference, args)

    # Mode 1: logarchive alone, mac auto-generates ref
    if _is_logarchive(source) and args.reference is None:
        if not is_macos():
            log.error("error: on this OS the reference ndjson must be supplied explicitly.\n"
                "       Generate it on a Mac with:\n"
                "           log show --style ndjson --info --debug --signpost <archive> > ref.ndjson")
            return 1
        ref_path = _make_reference(source, args, resources, keep_paths)
        db_path = _extract_logarchive(source, args, resources, keep_paths)
        return _run_compare(db_path, ref_path, args)

    log.error(f"error: cannot interpret SOURCE {source} — "
        f"expected a .logarchive directory or a SQLite database file.")
    return 1


# ── Acquisition / extraction helpers ──────────────────────────────────────────

def _print_devices_or_help() -> int:
    """No arguments: on mac, list devices; otherwise nudge the user toward --help."""
    from forensic_aul.testing.platform import is_macos, list_devices

    if not is_macos():
        log.error("Nothing to do. Try `forensic-aul test --help`.")
        return 1
    try:
        devices = list_devices()
    except Exception as exc:
        log.error(f"error: could not enumerate devices: {exc}")
        return 1
    if not devices:
        print("No iOS devices connected. Plug one in (and trust the host) to use --from-device.")
        return 1
    print("Connected iOS devices:")
    for d in devices:
        print(f"  • {d.display()}")
    print("")
    print("Run again with --from-device <NAME_OR_UDID> to start the full pipeline.")
    return 0


def _collect_from_device(
    name_or_udid: str | None,
    resources: _Resources,
) -> Path:
    """Acquire a fresh logarchive from the resolved device."""
    from forensic_aul.testing import log_collect
    from forensic_aul.testing.platform import resolve_device

    device = resolve_device(name_or_udid)
    log.info(f"Acquiring from device: {device.display()}")

    out_dir = resources.tempdir(prefix="forensic_aul_collect_")
    return log_collect.run(device.udid, out_dir)


def _make_reference(
    logarchive: Path,
    args: argparse.Namespace,
    resources: _Resources,
    keep_paths: set[Path],
) -> Path:
    """Run `log show` to produce the reference ndjson."""
    from forensic_aul.testing import log_show

    flags = log_show.DEFAULT_FLAGS
    if args.log_show_args:
        flags = tuple(shlex.split(args.log_show_args))

    out_dir = resources.tempdir(prefix="forensic_aul_ref_")
    out_path = out_dir / (logarchive.name + ".ndjson")

    ref = log_show.run(logarchive, out_path, flags=flags)
    if args.keep_ref:
        keep_paths.add(ref.resolve())
        log.info(f"Reference ndjson kept at: {ref}")
    return ref


def _extract_logarchive(
    logarchive: Path,
    args: argparse.Namespace,
    resources: _Resources,
    keep_paths: set[Path],
) -> Path:
    """Run our parser on the logarchive and return the DB path."""
    from forensic_aul.ops.extraction.extract import run_extract

    if args.db_output:
        db_path = args.db_output
        db_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        out_dir = resources.tempdir(prefix="forensic_aul_test_")
        db_path = out_dir / (logarchive.name + ".db")

    log.info(f"Extracting {logarchive} → {db_path}")
    run_extract(
        logarchive=logarchive,
        db_path=db_path,
        case_number=args.case_number,
        imei=args.imei,
        exhibit_number=None,
        analyst_name=None,
        notes="auto-generated by forensic-aul test",
        batch_size=getattr(args, "batch_size", 1_000),
    )
    if args.keep_db:
        keep_paths.add(db_path.resolve())
        log.info(f"Database kept at: {db_path}")
    return db_path


# ── Comparison ────────────────────────────────────────────────────────────────

def _run_compare(
    db_path: Path,
    ref_path: Path,
    args: argparse.Namespace,
) -> int:
    """Load both sides, run the comparator, render the report, decide exit code."""
    from forensic_aul.testing.comparator import compare, load_db_records, render_report
    from forensic_aul.testing.ndjson_loader import load_ndjson

    # ── Load reference ────────────────────────────────────────────────────────
    log.info(f"Loading reference ndjson: {ref_path}")
    ref = load_ndjson(ref_path)
    log.info(f"Reference loaded : {ref.count} records  (skipped: {dict(ref.skipped_event_types)}  user_action: {ref.user_action_count}  collisions: {ref.collisions})")

    # ── Load DB ───────────────────────────────────────────────────────────────
    log.info(f"Loading database: {db_path}")
    db_records = load_db_records(db_path)

    # ── Optional ndjson export ────────────────────────────────────────────────
    if args.ndjson_output:
        from forensic_aul.testing.ndjson_exporter import export_db_to_ndjson
        ndjson_out: Path = args.ndjson_output
        ndjson_out.parent.mkdir(parents=True, exist_ok=True)
        n = export_db_to_ndjson(db_records, ndjson_out)
        log.info(f"ndjson export: {n} records → {ndjson_out}")

    # ── Compare ───────────────────────────────────────────────────────────────
    log.info("Running comparison…")
    report = compare(ref, db_records, max_samples=args.samples)

    text = render_report(report)
    if args.report:
        try:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(text, encoding="utf-8")
            log.info(f"Report written to: {args.report}")
        except OSError:
            log.exception("Could not write report file")

    # ── Pass / fail ───────────────────────────────────────────────────────────
    missing = report.ref_total - report.matched
    if missing > args.allow_missing:
        log.error(f"FAIL: {missing} reference record(s) missing from the DB (allowed: {args.allow_missing}).")
        return 1
    log.info("PASS: every reference record is present in the DB.")
    return 0
