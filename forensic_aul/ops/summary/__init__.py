"""Summary operation — read-only high-level view of an analysis database.

``summary.summarise`` runs the read-only queries (counts, top-N, annotation
rollup, temporal histogram) and returns a ``Summary``. Rendering lives in
``report``; this operation never prints.
"""
