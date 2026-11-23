#!/usr/bin/env python3
"""Regenerate the iOS build-code → version table from the ipsw.me firmware API.

Defines : a maintainer script that fetches the signed-and-unsigned IPSW firmware
          list of a few devices from ``https://api.ipsw.me/v4/device/<id>?type=ipsw``
          (fields ``version`` and ``buildid``), merges them with the table on
          disk, and rewrites ``forensic_aul/engine/ios_builds.json``.
Used by : maintainers, by hand: ``python scripts/update_ios_builds.py``. With
          ``--check`` it writes nothing and exits 1 when the fetch would add
          builds (for a periodic job).
Uses    : the standard library only (urllib, json); the table format read by
          forensic_aul/engine/ios_builds.py.

WHY several devices: a build ships only for the devices it supports, so one
device's list misses both older releases and device-specific builds. The
defaults span generations (iPhone 11, 14 Pro, 16 Pro and an iPad Pro); pass
``--device`` to add others. A device the API does not know is reported and
skipped, never fatal.

WHY merge and never drop: a build that falls off the API (very old devices are
pruned) is still a correct mapping. And a build the API maps to a different
version than the table already holds is a contradiction a human must resolve,
so the script stops instead of choosing.

Network: one HTTPS GET per device; nothing about a case is sent.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path

TABLE_PATH = Path(__file__).resolve().parents[1] / "forensic_aul" / "engine" / "ios_builds.json"
API_URL = "https://api.ipsw.me/v4/device/{identifier}?type=ipsw"
SOURCE_NAME = "api.ipsw.me v4 (type=ipsw)"
DEFAULT_DEVICES = ("iPhone12,1", "iPhone15,2", "iPhone17,1", "iPad13,4")
_TIMEOUT_S = 30


class ConflictError(Exception):
    """One build code mapped to two different versions."""


def fetch_device(identifier: str) -> dict[str, str]:
    """``{buildid: version}`` for one device (raises urllib errors)."""
    request = urllib.request.Request(
        API_URL.format(identifier=identifier),
        headers={"Accept": "application/json", "User-Agent": "forensic-aul-build-table"},
    )
    with urllib.request.urlopen(request, timeout=_TIMEOUT_S) as response:
        payload = json.load(response)
    return {fw["buildid"].upper(): fw["version"] for fw in payload.get("firmwares", [])
            if fw.get("buildid") and fw.get("version")}


def merge(existing: dict[str, str], fetched: dict[str, str]) -> dict[str, str]:
    """Union of both tables; raises ConflictError on a contradictory mapping."""
    merged = dict(existing)
    conflicts = []
    for build, version in fetched.items():
        known = merged.get(build)
        if known is not None and known != version:
            conflicts.append(f"{build}: table says {known}, source says {version}")
            continue
        merged[build] = version
    if conflicts:
        raise ConflictError("; ".join(conflicts))
    return dict(sorted(merged.items()))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--device", action="append", default=[],
                        help="extra device identifier to fetch (repeatable)")
    parser.add_argument("--check", action="store_true",
                        help="write nothing; exit 1 if new builds are available")
    args = parser.parse_args(argv)

    document = json.loads(TABLE_PATH.read_text(encoding="utf-8"))
    existing = document["builds"]
    fetched: dict[str, str] = {}
    for identifier in (*DEFAULT_DEVICES, *args.device):
        try:
            device_builds = fetch_device(identifier)
        except (urllib.error.URLError, ValueError, KeyError) as exc:
            print(f"skip {identifier}: {exc}", file=sys.stderr)
            continue
        print(f"{identifier}: {len(device_builds)} builds")
        fetched = merge(fetched, device_builds)

    try:
        merged = merge(existing, fetched)
    except ConflictError as exc:
        print(f"refusing to write — conflicting mappings: {exc}", file=sys.stderr)
        return 2
    added = sorted(set(merged) - set(existing))
    print(f"{len(existing)} builds on disk, {len(added)} new")
    if args.check:
        return 1 if added else 0
    if not added:
        return 0
    document["builds"] = merged
    document["source"] = SOURCE_NAME
    document["updated"] = date.today().isoformat()
    TABLE_PATH.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {TABLE_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
