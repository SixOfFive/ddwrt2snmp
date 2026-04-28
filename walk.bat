@echo off
rem Stdlib-only snmpget/snmpwalk client. Useful on Windows where snmpwalk
rem is not installed by default.
rem
rem Examples:
rem   walk 127.0.0.1:1161 1.3.6.1.2.1.1
rem   walk --get 127.0.0.1:1161 1.3.6.1.2.1.1.5.0
rem   walk -v 1 -c public 127.0.0.1:1161 1.3.6.1.2.1
rem   walk --bulk 10 127.0.0.1:1161 1.3.6.1

setlocal
set "SCRIPT_DIR=%~dp0"
if defined PYTHONPATH (
    set "PYTHONPATH=%SCRIPT_DIR%;%PYTHONPATH%"
) else (
    set "PYTHONPATH=%SCRIPT_DIR%"
)
python -m ddwrt2snmp.walk %*
endlocal
