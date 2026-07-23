#!/usr/bin/env bash
# Run the unit test suite across every supported Python (3.11–3.14).
#
# Uses uv: each interpreter gets its own throwaway environment (under TMPDIR) so
# the project's .venv is left untouched. uv downloads any missing interpreter
# automatically. Exits non-zero if the suite fails on ANY version.
#
# Usage:   ./scripts/test_matrix.sh            # unit suite on 3.11–3.14
#          PYS="3.12 3.13" ./scripts/test_matrix.sh   # a subset
#
# Integration tests are excluded here: they need the large sample acquisitions in
# tests/data/ and take ~40 min — run those separately on one interpreter.
set -euo pipefail
cd "$(dirname "$0")/.."

versions=(${PYS:-3.11 3.12 3.13 3.14})
envroot="${TMPDIR:-/tmp}/faul-test-venvs"
fail=0

for v in "${versions[@]}"; do
    echo "===================== Python $v ====================="
    if ! UV_PROJECT_ENVIRONMENT="$envroot/py$v" uv run --python "$v" --extra dev --quiet \
            pytest tests/unit -q; then
        echo ">>> FAILED on Python $v"
        fail=1
    fi
done

if [ "$fail" -eq 0 ]; then
    echo "All versions passed: ${versions[*]}"
fi
exit "$fail"
