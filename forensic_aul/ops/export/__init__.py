"""Export subsystem — filtered export of an analysis database.

Defines : the export logic (``run_export``) that streams rows from an extracted
          (and optionally annotated) SQLite database to CSV / JSON / JSONL, with
          column/time/knowledge-base filters. Knowledge-base aware: extracted
          fields become dedicated columns (CSV) or nested objects (JSON).
Used by : forensic_aul/__init__.py (re-exports ``run_export``) and
          launcher/cmds/export_cmd.py (argparse glue → ``run_export``).
Uses    : the standard library only (sqlite3, csv, json).

Public API:

    from forensic_aul import LogFilter, run_export
    run_export(db, "out.csv", LogFilter(level="Error"), fmt="csv")
"""
