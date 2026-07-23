"""Knowledge base — load, model and lint the YAML signature library.

``loader`` parses the repo-root ``knowledge_base/`` YAML tree into the
``models`` dataclasses (``KnowledgeBase``, ``Signature``); ``lint`` validates a
KB and suggests fixes. The ``annotate`` operation
(``forensic_aul.ops.annotation``) consumes the loaded KB; the ``kb`` command
inspects and validates it.

Public API:

    from forensic_aul.ops.knowledge_base.loader import load_kb, KnowledgeBaseError
"""
