#!/usr/bin/env bash
#
# Run the complete unit-test suite for django-oauth-toolkit.
#
# Usage:
#   ./test.sh                # run every unit test
#   ./test.sh path/to/test.py # run specific test module(s)
#
set -euo pipefail

cd "$(dirname "$0")"

if [ -x ".venv/bin/python" ]; then
    PYTHON=".venv/bin/python"
else
    PYTHON="python3"
fi

export DJANGO_SETTINGS_MODULE="${DJANGO_SETTINGS_MODULE:-tests.settings}"
export PYTHONPATH="$(pwd):${PYTHONPATH:-}"

echo "==> Ruff lint"
ruff check .

echo "==> Ruff format check"
ruff format --check .

echo "==> Django system checks"
"$PYTHON" -m django check

echo "==> Unit tests"
if [ "$#" -gt 0 ]; then
    "$PYTHON" -m pytest -p no:cacheprovider "$@"
else
    "$PYTHON" -m pytest -p no:cacheprovider tests/
fi

echo "==> All checks passed."
