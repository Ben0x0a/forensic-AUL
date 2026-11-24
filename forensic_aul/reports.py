"""Text renderers for the library's results — the public ``forensic_aul.reports``.

Defines : nothing itself; re-exports every ``format_*`` function: pure
          result → str, called at will by a frontend (the CLI prints them; a
          GUI or a third-party tool may show or log them).
Used by : launcher/cmds/* (the CLI commands).
Uses    : each brick's ``report`` module.

WHY a namespace of its own rather than the package root: the renderers are many
and only frontends want them; keeping them here leaves ``forensic_aul`` itself the
list of operations and data types. Names are qualified where the brick's own was
generic (``format_header`` of annotation → ``format_annotate_header``).
"""

from forensic_aul.ops.acquisition.report import format_acquire_result
from forensic_aul.ops.annotation.report import format_annotate_result
from forensic_aul.ops.annotation.report import format_header as format_annotate_header
from forensic_aul.ops.export.report import format_export_result
from forensic_aul.ops.identify.report import format_diff_result, format_identify_result, format_ranking
from forensic_aul.ops.knowledge_base.report import format_labels as format_kb_labels
from forensic_aul.ops.knowledge_base.report import format_signature as format_kb_signature
from forensic_aul.ops.knowledge_base.report import format_signature_list as format_kb_signature_list
from forensic_aul.ops.knowledge_base.report import (
    format_signature_list_json as format_kb_signature_list_json,
)
from forensic_aul.ops.knowledge_base.report import format_stats as format_kb_stats
from forensic_aul.ops.knowledge_base.report import format_validation as format_kb_validation
from forensic_aul.ops.summary.report import format_summary
from forensic_aul.ops.verify.report import format_verify

__all__ = [
    "format_acquire_result",
    "format_annotate_header",
    "format_annotate_result",
    "format_diff_result",
    "format_identify_result",
    "format_ranking",
    "format_export_result",
    "format_kb_labels",
    "format_kb_signature",
    "format_kb_signature_list",
    "format_kb_signature_list_json",
    "format_kb_stats",
    "format_kb_validation",
    "format_summary",
    "format_verify",
]
