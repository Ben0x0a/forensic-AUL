"""Best-effort iOS build-code → marketing-version lookup.

When an authoritative ``SystemVersion.plist`` is present (full-file-system and
sysdiagnose sources) the exact ``ProductVersion`` is used and this table is not
consulted. A bare ``.logarchive`` directory, however, carries only the **build
code** (e.g. ``21F90``) in its tracev3 header, so this maps a build back to a
human iOS version as a convenience.

IMPORTANT (forensic accuracy):
  - This table is intentionally PARTIAL and must be treated as best-effort. New
    builds ship constantly; an unknown build returns ``None`` and the caller
    keeps showing the raw build code rather than guessing.
  - Verify/extend entries against Apple's published build list before relying on
    them in a report. The authoritative source remains ``SystemVersion.plist``.

Used by : forensic_aul/extract.py (iOS-version fallback for logarchive-dir sources).
Uses    : nothing (a static table + a lookup helper).
"""

from __future__ import annotations

# build code (upper-case) → iOS marketing version. Seeded with recent iOS 17
# release builds; 21F90 is verified against a SystemVersion.plist in hand.
# Extend as needed — keep entries you can confirm.
IOS_BUILD_TO_VERSION: dict[str, str] = {
    # iOS 17.5.x
    "21F90": "17.5.1",
    "21F79": "17.5",
    # iOS 17.4.x
    "21E236": "17.4.1",
    "21E219": "17.4",
    # iOS 17.3.x
    "21D61": "17.3.1",
    "21D50": "17.3",
    # iOS 17.2.x
    "21C66": "17.2.1",
    "21C62": "17.2",
    # iOS 17.1.x
    "21B101": "17.1.2",
    "21B91": "17.1.1",
    "21B74": "17.1",
    # iOS 17.0.x
    "21A360": "17.0.3",
    "21A351": "17.0.2",
    "21A340": "17.0.1",
    "21A329": "17.0",
}


def ios_version_for_build(build: str | None) -> str | None:
    """Return the iOS marketing version for *build*, or None if unknown.

    Matching is exact and case-insensitive on the trimmed build code; a miss
    returns None so the caller can fall back to displaying the raw build.
    """
    if not build:
        return None
    return IOS_BUILD_TO_VERSION.get(build.strip().upper())
