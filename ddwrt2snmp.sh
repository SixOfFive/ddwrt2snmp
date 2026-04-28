#!/usr/bin/env bash
# Launcher for ddwrt2snmp on Linux/macOS.
# The default SNMP port (161) is privileged on Linux. Either run as root,
# grant the bind capability with:
#     sudo setcap 'cap_net_bind_service=+ep' "$(command -v python3)"
# or pass --bind with a high port (e.g. 127.0.0.1:1161).

set -e

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

if [ -n "${PYTHONPATH:-}" ]; then
    PYTHONPATH="${SCRIPT_DIR}:${PYTHONPATH}"
else
    PYTHONPATH="${SCRIPT_DIR}"
fi
export PYTHONPATH

exec python3 -m ddwrt2snmp "$@"
