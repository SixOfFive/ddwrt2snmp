@echo off
rem Launcher for ddwrt2snmp on Windows.
rem Note: the default SNMP port (161) requires Administrator on Windows
rem and conflicts with the Microsoft SNMP service if installed. Use --bind
rem with a high port (e.g. 127.0.0.1:1161) when running unprivileged.

setlocal
set "SCRIPT_DIR=%~dp0"
if defined PYTHONPATH (
    set "PYTHONPATH=%SCRIPT_DIR%;%PYTHONPATH%"
) else (
    set "PYTHONPATH=%SCRIPT_DIR%"
)
python -m ddwrt2snmp %*
endlocal
