#!/usr/bin/env bash
#
# Run the django-oauth-toolkit unit test suite.
#
# Usage:
#   ./test.sh                 # run all unit tests
#   ./test.sh tests/test_resource_indicators.py -v
#   PYTHON=/path/to/python ./test.sh
#
set -euo pipefail

cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"

export DJANGO_SETTINGS_MODULE="${DJANGO_SETTINGS_MODULE:-tests.settings}"
export PYTHONPATH="${PWD}${PYTHONPATH:+:${PYTHONPATH}}"

exec "${PYTHON}" -m pytest tests/ "$@"
