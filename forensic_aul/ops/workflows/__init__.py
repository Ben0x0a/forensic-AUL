"""Workflows — the only ops modules that chain other ops bricks.

Defines : nothing itself; ``identify`` (run_identify_workflow) and
          ``identify_options`` (IdentifyOptions, IDENTIFY_EXTRACT).
Used by : forensic_aul/__init__.py (re-exports), the CLI and the GUI.

WHY a separate layer: a brick (acquisition, extraction, annotation, identify,
export, query, summary, verify) does one job and never imports another brick's
operations — only shared data (models, options, the case info). Sequencing
several of them is a workflow's job, here (review finding S4).
"""
