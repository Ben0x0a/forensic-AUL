"""Ops — the callable operations of forensic_aul.

Each subpackage is one operation the tool can perform (acquisition, extraction,
annotation, knowledge_base, export, identify, summary, verify) and follows a
uniform shape:

  * a main module + any operation-specific helpers (pure: data in → data out),
  * a ``report`` module of ``format_*(outcome) -> str`` functions that a caller
    renders *at will* — ops never print or build a report themselves.

Prompting and pacing (when to ask, how to wait between steps) are deliberately
NOT here: they are frontend-bound (the CLI in ``launcher/``, the GUI in
``gui/``). Multi-step flows expose their steps and document the call sequence so
any frontend can drive them however it likes.
"""
