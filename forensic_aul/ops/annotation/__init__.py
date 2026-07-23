"""Annotation operation — apply a loaded knowledge base to an extracted database.

``matcher`` runs each signature's indexed pre-filter then its regex over the
``logs`` table, writing ``log_annotations`` and ``extracted_values`` rows. The
knowledge base itself (loading, linting, its data models) lives in the sibling
``forensic_aul.ops.knowledge_base`` package; this operation consumes a KB it
produces. The YAML signatures live in the repo-root ``knowledge_base/`` tree.

Public API:

    from forensic_aul.ops.annotation.matcher import annotate_database   # path-based
    from forensic_aul.ops.annotation.matcher import annotate_connection # connection-based
"""
