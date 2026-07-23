"""Engine — the pure backend of forensic_aul.

Everything here is operation-agnostic: binary-format parsing (``parser``), the
SQLite store (``database``), data models (``models``), integrity hashing
(``integrity``), reference data (``ios_builds``) and shared utilities
(``utils``). No module here knows about CLI commands, prompting, or human
presentation — that lives in ``forensic_aul.ops`` and the application layer.
"""
