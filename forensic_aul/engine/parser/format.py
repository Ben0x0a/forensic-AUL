"""Apple Unified Log on-disk format constants — the single source of recognition data.

Defines : chunk tags, header sub-chunk tags, magic signatures, compression ids
          and the shared structural sizes of the tracev3 / timesync / uuidtext /
          dsc formats.
Used by : every module in forensic_aul.engine.parser, forensic_aul.ops.extraction
          (chunk dispatch) and the tests.
Uses    : nothing — a pure-data leaf.

WHY one module: these values identify structures. Defined per parser they were
duplicated (the preamble size three times, three chunk tags twice), and a value
changed for a new OS version in one copy would silently disagree with another.
Constants used by a single parser only (e.g. Firehose flag bits) stay with it.
"""

# ── Chunk framing (tracev3 and the inside of a decompressed chunkset) ─────────
CHUNK_PREAMBLE_SIZE: int = 16  # tag (u32) + sub_tag (u32) + data_size (u64)
CHUNK_ALIGNMENT: int = 8       # each top-level chunk is padded to a multiple of 8 bytes

# ── Top-level tracev3 chunk tags ───────────────────────────────────────────────
CHUNK_TAG_HEADER: int = 0x1000
CHUNK_TAG_CATALOG: int = 0x600B
CHUNK_TAG_CHUNKSET: int = 0x600D

# ── Sub-chunk tags inside a decompressed chunkset ─────────────────────────────
CHUNK_TAG_FIREHOSE: int = 0x6001
CHUNK_TAG_OVERSIZE: int = 0x6002
CHUNK_TAG_STATEDUMP: int = 0x6003
CHUNK_TAG_SIMPLEDUMP: int = 0x6004

# ── Sub-chunk tags inside the tracev3 header chunk ────────────────────────────
HEADER_SUBCHUNK_TAG_0: int = 0x6100  # mach continuous time
HEADER_SUBCHUNK_TAG_1: int = 0x6101  # build version + hardware model
HEADER_SUBCHUNK_TAG_2: int = 0x6102  # boot UUID + logd info
HEADER_SUBCHUNK_TAG_3: int = 0x6103  # timezone path

# ── Chunkset payload signatures (little-endian u32 of 4 ASCII bytes) ──────────
SIG_BV41_COMPRESSED: int = 825521762    # b"bv41" — LZ4-compressed payload follows
SIG_BV41_UNCOMPRESSED: int = 758412898  # b"bv4-" — payload is stored uncompressed
SIG_BV4_FOOTER: int = 0x24347662        # b"bv4$" — terminator after payload

# ── Catalog sub-chunk compression algorithm ids ───────────────────────────────
CATALOG_COMPRESSION_LZ4: int = 0x100

# ── Timesync file signatures ──────────────────────────────────────────────────
TIMESYNC_BOOT_SIGNATURE: int = 0xBBB0      # u16 — start of a TimesyncBoot record
TIMESYNC_RECORD_SIGNATURE: int = 0x207354  # u32 — start of a Timesync record

# ── String-store signatures ───────────────────────────────────────────────────
UUIDTEXT_SIGNATURE: int = 0x66778899
DSC_SIGNATURE: int = 0x64736368  # b"hcsd" read as little-endian u32 ("dsch")

# Format-string offset flag shared by uuidtext and dsc: the format string is
# literally "%s" (a dynamic message).
DYNAMIC_STRING_OFFSET: int = 0x80000000
