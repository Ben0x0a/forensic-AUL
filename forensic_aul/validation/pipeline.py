"""The ``validate`` self-check pipeline: acquire / generate-reference / extract / compare.

This is QA tooling, not a user-facing operation — it orchestrates the extract
pipeline, Apple's ``log show``/``log collect`` CLIs, and the comparator to prove
our output matches Apple's ground truth. It is non-interactive: the argument
*shape* selects the mode, and everything else runs to completion. The CLI
handler (``launcher/cmds/validate_tool_cmd.py``) only parses arguments and calls
:func:`run`.

Source forms (auto-detected by file shape):

  validate                                 # mac: list devices, refuse otherwise
  validate --from-device [NAME_OR_UDID]    # mac: collect → show → extract → diff
  validate <logarchive> [ref.ndjson]       # extract → diff (ref auto-made on mac)
  validate <db.sqlite>  <ref.ndjson>       # diff only
  validate <db.sqlite>  --regen-ref <logarchive>   # mac: re-make ref, then diff
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
    from forensic_aul.validation.platform import capabilities
    log.info(f"validate: environment — {capabilities().summary()}")
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
    from forensic_aul.validation.platform import is_macos

    # Mode L2: --acquisition A B → file-level acquisition-fidelity check (parser-free,
    # cross-platform, no root). Checked first: it needs neither a device nor `log`.
    if getattr(args, "acquisition", None):
        return _run_acquisition_compare(args)

    # Mode "no args": list devices on macOS, otherwise help.
    if args.source is None and args.from_device is None and args.regen_ref is None:
        return _print_devices_or_help()

    # Mode L3: --from-device → acquire the same device both ways, check acquisition
    # (L2) + parser (L1). Needs macOS + root (Apple `log collect`).
    if args.from_device is not None:
        return _run_l3_from_device(args, resources, keep_paths)

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
    from forensic_aul.validation.platform import is_macos, list_devices

    if not is_macos():
        log.error("Nothing to do. Try `forensic-aul validate-tool --help`.")
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
    udid: str,
    resources: _Resources,
    *,
    last: str | None = None,
) -> Path:
    """Acquire a logarchive from *udid* via Apple ``log collect`` (needs root)."""
    from forensic_aul.validation import log_collect

    out_dir = resources.tempdir(prefix="forensic_aul_collect_")
    return log_collect.run(udid, out_dir, last=last)


def _acquire_pymobiledevice3(udid: str, args: argparse.Namespace, resources: _Resources) -> Path:
    """Acquire a loose logarchive from *udid* via pymobiledevice3 (userspace)."""
    from forensic_aul.ops.acquisition.acquire import acquire

    out_dir = resources.tempdir(prefix="forensic_aul_pmd3_")
    result = acquire(
        case_number="VALIDATE-L3",
        output_dir=out_dir,
        udid=udid,
        start_time=getattr(args, "collect_last", None),
        pack=False,   # loose .logarchive (no .faul wrapper)
    )
    return result.logarchive_path


def _run_l3_from_device(
    args: argparse.Namespace,
    resources: _Resources,
    keep_paths: set[Path],
) -> int:
    """L3 full-native check: acquire the SAME device both ways, then verify
    acquisition equivalence (L2, file-level) and parser fidelity (L1) on the
    metadata-complete ``log collect`` archive. Needs macOS + root."""
    from forensic_aul.validation.archive_compare import compare_archives, render_archive_report
    from forensic_aul.validation.platform import capabilities, resolve_device

    caps = capabilities()
    if not caps.is_macos:
        log.error("--from-device needs macOS (Apple `log collect`). Elsewhere, run "
                  "`validate --acquisition <A> <B>` for the acquisition check and supply a "
                  "reference ndjson for the parser check.")
        return 1
    if not caps.is_root:
        log.error("--from-device needs root for `log collect` — run "
                  "`sudo faul.py validate-tool --from-device`. (pymobiledevice3 `acquire` is the "
                  "userspace alternative and needs no root.)")
        return 1

    device = resolve_device(args.from_device or None)
    log.info(f"L3 full-pipeline validation on: {device.display()}")

    # Acquire both ways, back-to-back, to minimise live-log drift (the append-check
    # in L2 absorbs whatever tail grows between the two collections).
    archive_pmd3 = _acquire_pymobiledevice3(device.udid, args, resources)
    archive_collect = _collect_from_device(device.udid, resources, last=getattr(args, "collect_last", None))

    # L2 — acquisition fidelity (file-level, parser-free).
    l2 = compare_archives(archive_pmd3, archive_collect,
                          label_a="pymobiledevice3", label_b="log-collect")
    for line in render_archive_report(l2).splitlines():
        log.info("%s", line)

    # L1 — parser fidelity on the metadata-complete log-collect archive.
    ref_path = _make_reference(archive_collect, args, resources, keep_paths)
    db_path = _extract_logarchive(archive_collect, args, resources, keep_paths)
    l1_code = _run_compare(db_path, ref_path, args)

    log.info(f"L3 result: acquisition (L2) = {'PASS' if l2.passed else 'FAIL'}  ·  "
             f"parser (L1) = {'PASS' if l1_code == 0 else 'FAIL'}")
    return 0 if (l2.passed and l1_code == 0) else 1


def _make_reference(
    logarchive: Path,
    args: argparse.Namespace,
    resources: _Resources,
    keep_paths: set[Path],
) -> Path:
    """Run `log show` to produce the reference ndjson."""
    from forensic_aul.validation import log_show

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
        notes="auto-generated by forensic-aul validate-tool",
        batch_size=getattr(args, "batch_size", 1_000),
    )
    if args.keep_db:
        keep_paths.add(db_path.resolve())
        log.info(f"Database kept at: {db_path}")
    return db_path


# ── L2 : acquisition comparison (file-level, parser-free) ─────────────────────

def _run_acquisition_compare(args: argparse.Namespace) -> int:
    """Compare two logarchives at the file level (SHA-256 + append-check)."""
    from forensic_aul.validation.archive_compare import compare_archives, render_archive_report

    archive_a, archive_b = args.acquisition
    for path in (archive_a, archive_b):
        if not Path(path).is_dir():
            log.error(f"error: not a logarchive directory: {path}")
            return 1

    result = compare_archives(archive_a, archive_b, label_a=archive_a.name, label_b=archive_b.name)
    text = render_archive_report(result)
    for line in text.splitlines():
        log.info("%s", line)
    if args.report:
        try:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(text, encoding="utf-8")
            log.info(f"Report written to: {args.report}")
        except OSError:
            log.exception("Could not write report file")

    if result.passed:
        log.info("PASS: the two acquisitions copied identical device files (append aside).")
        return 0
    log.error(f"FAIL: {len(result.diverged)} device file(s) diverged between the acquisitions.")
    return 1


# ── Comparison ────────────────────────────────────────────────────────────────

def _run_compare(
    db_path: Path,
    ref_path: Path,
    args: argparse.Namespace,
) -> int:
    """Stream both sides through the sort-merge comparator, render, decide exit code."""
    from forensic_aul.validation.comparator import render_report
    from forensic_aul.validation.merge_compare import merge_compare

    # ── Optional ndjson export ────────────────────────────────────────────────
    # Opt-in only: the exporter needs the DB rows in a dict, so this is the one
    # path that loads the DB into RAM. The comparison itself stays streaming.
    if args.ndjson_output:
        from forensic_aul.validation.comparator import load_db_records
        from forensic_aul.validation.ndjson_exporter import export_db_to_ndjson
        ndjson_out: Path = args.ndjson_output
        ndjson_out.parent.mkdir(parents=True, exist_ok=True)
        n = export_db_to_ndjson(load_db_records(db_path), ndjson_out)
        log.info(f"ndjson export: {n} records → {ndjson_out}")

    # ── Compare (flat-memory sort-merge on disk) ──────────────────────────────
    log.info(f"Comparing (streaming sort-merge): DB={db_path}  ref={ref_path}")
    report = merge_compare(db_path, ref_path, max_samples=args.samples)

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
