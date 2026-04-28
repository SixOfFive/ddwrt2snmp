#!/usr/bin/env bash
# Stdlib-only snmpget/snmpwalk client.
# Examples:
#   ./walk.sh 127.0.0.1:1161 1.3.6.1.2.1.1
#   ./walk.sh --get 127.0.0.1:1161 1.3.6.1.2.1.1.5.0
#   ./walk.sh --bulk 10 127.0.0.1:1161 1.3.6.1

set -e
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
if [ -n "${PYTHONPATH:-}" ]; then
    PYTHONPATH="${SCRIPT_DIR}:${PYTHONPATH}"
else
    PYTHONPATH="${SCRIPT_DIR}"
fi
export PYTHONPATH
exec python3 -m ddwrt2snmp.walk "$@"
