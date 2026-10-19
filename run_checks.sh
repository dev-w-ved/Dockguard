#!/usr/bin/env sh
set -eu

PYTHON="${PYTHON:-python3}"

"${PYTHON}" -m pip install -r requirements.txt

if [ "${1:-check}" = "server" ]; then
    exec "${PYTHON}" -m uvicorn dockguard.web.app:app --host "${HOST:-127.0.0.1}" --port "${PORT:-8080}"
fi

exec "${PYTHON}" -W error -m pytest -q
