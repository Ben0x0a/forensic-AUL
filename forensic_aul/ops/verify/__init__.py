"""Verify operation — re-check the chain of custody of an extracted database.

``verify.verify_database`` re-hashes the logarchive and the operational log
file, compares each digest against the value stored at extract time, and
returns a structured ``VerifyResult``. Rendering lives in ``report``; this
operation never prints.
"""
