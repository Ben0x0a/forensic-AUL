"""Extraction subsystem — the .logarchive → SQLite pipeline.

Defines : the extract pipeline (``run_extract``) and supporting sub-modules:
          ``source`` (input preparation), ``shutdown_log`` (sidecar parser),
          ``oversize_pass`` (Pass 1), ``entry_builder`` (Firehose→LogEntry),
          ``tracev3_parse`` (single-file loop), ``workers`` (multiprocessing),
          ``discovery`` (file-system search), ``timesync_setup`` (anchor
          pre-insertion).
Used by : forensic_aul/__init__.py (re-exports ``run_extract``), launcher/* (CLI
          extract/acquire/identify/test subcommands), and external callers.
Uses    : forensic_aul.engine.integrity (hashing), forensic_aul.engine.database
          (schema/writer/ordering), forensic_aul.engine.parser (tracev3/firehose),
          forensic_aul.engine.ios_builds (build → iOS version lookup).

Public API:

    from forensic_aul.ops.extraction.extract import run_extract
"""
