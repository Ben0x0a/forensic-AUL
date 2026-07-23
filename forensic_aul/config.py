"""Centralized operational defaults for AUL Parser.

What belongs here
-----------------
Tunable defaults that affect performance or behaviour and that a developer
might want to change across the codebase without hunting through multiple
files.  These are the values used when no CLI argument or explicit override
is provided.

What does NOT belong here
--------------------------
- Binary format magic numbers (0x600b, 0xBBB0, etc.) — those are Apple
  specifications; they live in their respective parser modules where they
  serve as inline documentation of the file format.
- Schema constants (column names, table names) — those live in schema.py.

Usage
-----
    from forensic_aul.config import BATCH_SIZE, HASH_CHUNK_SIZE

All values are plain Python constants so they are visible to the type
checker and can be imported with zero overhead.
"""

from __future__ import annotations

# ── Database write performance ────────────────────────────────────────────────

# Number of log entries accumulated before a single executemany() + commit().
# Higher values → fewer round-trips (each commit is a WAL sync), more RAM.
# 10 000 is the default: on a multi-million-row archive it cuts the number of
# commits/syncs ~10x versus 1 000 while the pending batch stays only a few MB.
# Raise further (e.g. 50 000) on RAM-rich hosts; lower it on tiny machines.
BATCH_SIZE: int = 10_000

# WAL auto-checkpoint threshold, in pages (consumed by database/schema.py:apply_pragmas).
# SQLite's default is 1 000 pages (~4 MiB at the 4 KiB page size); over a multi-GB
# bulk load that forces near-constant checkpoints, each rewriting WAL pages back
# into the main DB and inflating total bytes written several-fold. A larger
# threshold checkpoints far less often (the WAL grows to ~this size between
# checkpoints) which markedly reduces write amplification on big extracts.
WAL_AUTOCHECKPOINT_PAGES: int = 20_000  # ~80 MiB at a 4 KiB page

# ── Ordering finalisation (consumed by database/ordering.py:assign_ordering) ───

# Rows per batch when writing the post-load ordering columns (source_order,
# event_order) back into ``logs``. WHY batched: assign_ordering used to UPDATE all
# ~40 M rows in ONE transaction, so the WAL grew to the size of a whole-table
# rewrite (observed 24 GB) and filled the disk mid-run. Committing and truncating
# the WAL after every batch caps it at roughly one batch's worth of dirtied pages.
# The final ordering is computed in full beforehand, so batching the write-back
# changes nothing about the result — only the WAL footprint. Lower on tiny disks.
ORDERING_UPDATE_BATCH_ROWS: int = 2_000_000

# Page-cache size (SQLite ``PRAGMA cache_size``; negative ⇒ KiB) applied only for
# the duration of the ordering pass, then restored. WHY larger here: the batched
# UPDATE re-reads the table by id, and a bigger cache keeps that working set in RAM
# instead of forcing the hundreds of GB of re-reads measured with the default
# 64 MiB cache. ~1 GiB; lower it on memory-constrained hosts.
ORDERING_CACHE_SIZE_KIB: int = -1_048_576  # 1 GiB

# ── Parallelism auto-defaults (consumed by engine/utils/system.py:resolve_auto_jobs) ─

# Upper bound on the auto-derived ``--jobs`` value (total process budget:
# N-1 parser workers + 1 writer). WHY a cap below the core count: benchmarking a
# 47 M-row logarchive on a 10-core M2 Pro showed parse throughput plateaus at ~6
# jobs (3.20x over serial) and *regresses* at 10 (3.11x, +5% wall, +1 GB RSS) —
# the extra processes contend for memory bandwidth and the writer/ordering tail
# without adding parse speed. 8 keeps a little headroom over the observed knee
# while still avoiding the regression. An explicit ``--jobs N`` overrides this.
JOBS_AUTO_CAP: int = 8

# Estimated resident memory each extra parser process holds (its private UUIDText
# / format-string cache plus interpreter overhead). WHY ~0.3 GiB: the CLI help and
# observed worker RSS put the string cache at ~150-250 MB; rounding up leaves slack
# so the memory-aware default does not over-subscribe RAM. Consumed when dividing
# available memory into a safe worker count.
JOBS_WORKER_RSS_GIB: float = 0.30

# Memory held back from the auto-jobs budget for everything that is NOT a parser
# worker: the writer process's page cache, the OS, and especially the post-load
# ordering / index / FTS phases (single-connection, multi-GB peak RSS regardless
# of job count). WHY reserve rather than count workers exactly: those tail phases
# dominate peak memory, so the reserve — not the per-worker estimate — is what
# protects a memory-constrained host from swapping.
JOBS_MEMORY_RESERVE_GIB: float = 4.0

# ── Forensic hashing ──────────────────────────────────────────────────────────

# Size of the read chunks used when computing SHA-256 of individual files.
# 1 MiB is a good balance between syscall count and memory pressure.
HASH_CHUNK_SIZE: int = 1 << 20  # 1 MiB

# ── Parser safety limits ──────────────────────────────────────────────────────

# Hard ceiling on the decompressed size of a single chunkset (one LZ4 block).
# Real Apple Unified Log chunksets are far smaller; a header claiming more
# indicates a corrupt or crafted tracev3. WHY this matters: the claimed size is
# handed to lz4, which PRE-ALLOCATES that many bytes before decompressing — so an
# unbounded value (up to ~4 GiB) is a memory-exhaustion vector. decompress_chunkset
# refuses anything above this cap. Consumed by parser/chunkset.py.
MAX_CHUNKSET_DECOMPRESSED_SIZE: int = 256 * 1024 * 1024  # 256 MiB

# ── String cache ──────────────────────────────────────────────────────────────

# Maximum number of UUIDText entries to keep in the in-process cache.
# Each entry holds a few KB of format strings.  0 = unlimited.
UUIDTEXT_CACHE_MAX: int = 0

# Per-file cap on the (offset → resolved format string) memo attached to each
# parsed UUIDText / DSC object (consumed by parser/uuidtext.py and parser/dsc.py).
# The same format-string offset recurs across millions of log entries, so memoising
# the resolved string per offset removes the descriptor scan / binary search from
# the per-entry hot path. The cap is a forensic safety guard: a corrupt or crafted
# tracev3 that references a huge number of *distinct* offsets cannot grow the memo
# without bound. Real files reference only a few thousand distinct offsets, so this
# cap is never reached in practice; once hit, further offsets are resolved without
# being cached (correctness is unaffected, only speed).
FORMAT_STRING_OFFSET_CACHE_MAX: int = 200_000

# ── Logging — separator ───────────────────────────────────────────────────────

# Width used for the separator lines in the operational log
# (e.g. "═" * LOG_SEPARATOR_WIDTH).
LOG_SEPARATOR_WIDTH: int = 72

# ── Logging — console handler format ─────────────────────────────────────────
#
# Shows: time | level (padded) | file:line (padded) | function (padded) |
#        processName[pid] | message
#
# The extra whitespace is intentional: it aligns columns when records from
# different modules (varying filename / funcname lengths) are printed together.
#
LOG_CONSOLE_FORMAT: str = (
    "%(asctime)s  "
    "%(levelname)-8s  "
    "%(filename)-28s:%(lineno)-4d  "
    "%(funcName)-30s  "
    "%(processName)s[%(process)d]"
    " — %(message)s"
)
LOG_CONSOLE_DATEFMT: str = "%H:%M:%S"

# ── Logging — file handler format ────────────────────────────────────────────
#
# Clean format for the audit-trail log file: no source location, no process
# info — just a UTC timestamp, level, a fixed source label, and the message.
#
LOG_FILE_FORMAT: str = (
    "%(asctime)s  "
    "%(levelname)-8s  "
    "Forensic AUL"
    " — %(message)s"
)
LOG_FILE_DATEFMT: str = "%Y-%m-%dT%H:%M:%SZ"
