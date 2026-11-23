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

### LZBITMAP decoder

`forensic_aul/engine/parser/lzbitmap.py` is a Python port of `src/lzbitmap.rs` from
`macos-unifiedlogs` **v0.7.0**, which is itself based on
`dissect/util/compression/lzbitmap.py` from **Fox-IT `dissect.util`**. The port
follows the Rust version (it also decodes the non-run-length variant iOS 27
writes) and is re-structured for Python; its output is verified against Apple's
libcompression (`COMPRESSION_LZBITMAP`) in `tests/parser/test_lzbitmap.py`.

## Fox-IT `dissect.util`

- Project: https://github.com/fox-it/dissect.util
- Licence: Apache License 2.0
- Copyright notice: "Dissect is released as open source by Fox-IT
  (https://www.fox-it.com) part of NCC Group Plc (https://www.nccgroup.com).
  Developed by the Dissect Team (dissect@fox-it.com) and made available at
  https://github.com/fox-it/dissect.util"

Used only through the LZBITMAP decoder described above (via the upstream Rust
port). A copy of its Apache 2.0 licence text is kept at
[`licenses/dissect.util-LICENSE`](licenses/dissect.util-LICENSE).
