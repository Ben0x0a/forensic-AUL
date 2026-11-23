"""The single source of the package version.

Defines : __version__.
Used by : forensic_aul/__init__.py (re-exported as forensic_aul.__version__),
          pyproject.toml ([tool.setuptools.dynamic] reads it without importing),
          and library modules that stamp the version into artefacts
          (ops/extraction/extract.py, ops/acquisition/report.py, engine/database/summary_cache.py).
Uses    : nothing — a leaf module, so any module may import it without a cycle.
"""

__version__ = "0.1.0"
