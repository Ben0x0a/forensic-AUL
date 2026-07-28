"""AUL Parser — application orchestration layer.

Defines : the orchestration layer that sits between the shipped ``forensic_aul``
          library and the thin shells (``launcher``, ``gui``). It holds
          cross-cutting run orchestration — the extraction *session* runner and
          the crash-report/diagnostics machinery — that is neither pure forensic
          domain logic (that lives in ``forensic_aul``) nor a shell/UI concern
          (that lives in ``launcher`` / ``gui``).
Used by : launcher.* and gui.* (the shells call into this layer).
Uses    : forensic_aul.* only. Dependencies flow inward: this layer may import the
          library but never the shells, and the library never imports this layer.

WHY a separate top-level package (not ``forensic_aul/app``): the project ships
only ``forensic_aul*`` (the library + its stable read API); ``launcher`` and
``gui`` are clone-&-run application code. This orchestration layer is application
infrastructure, so it lives beside the shells, outside the shipped library.
"""
