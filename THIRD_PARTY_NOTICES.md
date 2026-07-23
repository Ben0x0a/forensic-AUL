# Third-party notices

This project includes material derived from third-party open-source software.

## Mandiant `macos-unifiedlogs`

The Apple Unified Log binary parser in `forensic_aul/engine/parser/` is a Python
port of the structures and decoders in the **Mandiant `macos-unifiedlogs`** Rust
library.

- Project: https://github.com/mandiant/macos-UnifiedLogs
- Licence: Apache License 2.0

In particular, the os_log annotation value→name decoder tables in
`forensic_aul/engine/parser/decoder_tables.py` are **auto-generated** by
`scripts/gen_decoders.py`, which fetches that library's `src/decoders/` source
**directly from the upstream GitHub repository** (nothing is vendored in this
repo). The generated module carries the same attribution in its header. Only pure
value→name lookup tables are ported; byte-parsing decoders are re-implemented
independently in `forensic_aul/engine/parser/message.py`. Parser docstrings cite
the upstream file that documents each binary layout (e.g. `macos-UnifiedLogs/src/…`).

A copy of the Apache 2.0 licence text accompanying the upstream work is kept at
[`licenses/macos-UnifiedLogs-LICENSE`](licenses/macos-UnifiedLogs-LICENSE).
