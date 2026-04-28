# ddwrt2snmp

A standalone SNMPv1/v2c agent that scrapes a DD-WRT router over telnet and
serves the data on the SNMP wire. One process per router.

DD-WRT does not ship a usable SNMP agent for everything you'd want to graph
(per-radio temperatures, wireless association lists, bridge FDB, etc.).
This bridges the gap: telnet in, parse the same files DD-WRT's own web UI
reads, and expose the values under standard MIBs (plus a private subtree for
DD-WRT-specific data) on a UDP port your network monitor can poll.

## Requirements

- Python 3.8+
- A DD-WRT router with telnet enabled (Services -> Services -> Telnetd)
- No third-party packages. Pure stdlib: `socket`, `selectors`, `threading`,
  `re`, `argparse`. The whole agent including the SNMP codec is hand-rolled.

## Quick start

Linux / macOS:
```sh
chmod +x ddwrt2snmp.sh
./ddwrt2snmp.sh --target 192.168.1.1 \
                --user root --password 'YOURPASS' \
                --bind 0.0.0.0:1161
```

Windows:
```bat
ddwrt2snmp.bat --target 192.168.1.1 --user root --password YOURPASS --bind 0.0.0.0:1161
```

Then point any SNMP manager at `host:1161`, community `public`, version `2c`.

For a quick smoke test there's a stdlib snmpwalk/snmpget client included:
```sh
./walk.sh 127.0.0.1:1161 1.3.6.1.2.1.1                   # walk system group
./walk.sh --get 127.0.0.1:1161 1.3.6.1.2.1.1.5.0         # get sysName
./walk.sh 127.0.0.1:1161 1.3.6.1.4.1.99999.1.2           # walk temperatures
```

Two routers? Run two instances on different ports:
```sh
./ddwrt2snmp.sh --target 192.168.1.1 --user root --password A --bind 0.0.0.0:1161 &
./ddwrt2snmp.sh --target 192.168.1.2 --user root --password B --bind 0.0.0.0:1162 &
```

## CLI options

```
--target HOST[:PORT]    DD-WRT telnet target (default port 23)
--user USER             telnet username
--password PASSWORD     telnet password
--bind HOST[:PORT]      SNMP listen address (default 127.0.0.1:161)
--snmp-version {1,2c}   SNMP version to serve (default 2c)
--community STR         SNMP community (default 'public')
--poll-interval SECONDS seconds between telnet polls (default 60)
--flush-after-failures N flush cache to UNREACHABLE marker after N
                        consecutive failed polls (default 3, 0 to disable)
--log-level LEVEL       DEBUG | INFO | WARNING | ERROR (default INFO)
```

Port 161 is privileged on Linux. Either run as root, grant the bind
capability once with `sudo setcap 'cap_net_bind_service=+ep'
"$(command -v python3)"`, or use a high port like 1161.

## How it works

```
+--------------+    telnet     +-----------+   bulk_replace   +-------+    UDP    +-------------+
|  DD-WRT      | <-----------> |  Poller   | ---------------> | Cache | <-------> | SNMP agent  |
|  (BusyBox)   |   shell cmds  |  (thread) |  741..900 OIDs   | (lex) |  Get/     | (UDP loop)  |
+--------------+   per minute  +-----------+                  +-------+  GetNext/ +-------------+
                                                                         GetBulk
```

The poller runs in a daemon thread on a persistent telnet session. Each tick:
1. Runs ~17 commands (`uname`, `cat /proc/net/dev`, `ifconfig`, `nvram get`,
   `wl phy_tempsense` or `cat /sys/class/thermal/thermal_zone*/temp`,
   `wl assoclist` or `iw <iface> station dump`, `brctl showmacs`, etc.).
2. Parses each output via a pure function in `parsers.py`.
3. Builds a flat `{oid_tuple: SNMPValue}` dict via builders in `mibs.py`.
4. Atomically swaps the cache via `bulk_replace`.

Per-command failures (non-zero exit, missing tool, missing file) are soft:
the value just doesn't appear in the cache that cycle. Only telnet I/O
errors trigger a reconnect with exponential backoff (1s, 2s, 4s, ...,
capped at the poll interval).

After `--flush-after-failures` consecutive failed polls (default 3) the
cache is replaced with a minimal "UNREACHABLE" marker: the system group
has sysDescr set to a string like
`DD-WRT (via ddwrt2snmp) -- UNREACHABLE at HOST:PORT since TIMESTAMP`,
and every other table is empty. This stops stale interface counters,
temperatures, and CPU values from continuing to look like live data to
your monitor. The first successful poll after recovery rebuilds the
full cache.

The SNMP agent serves Get / GetNext / GetBulk from the cache. Lexicographic
OID order is preserved by the cache's sorted index so `snmpwalk` traversal
works correctly. SetRequest returns `noAccess`; this is a read-only agent.

The telnet client is a raw socket with an IAC state machine that refuses
every option (stays in NVT mode), auto-detects login/password prompts
case-insensitively, and brackets each command with a unique sentinel
(`__SX_XXXXXX_YYYY__=$?=` followed by the shell prompt) so output parsing
is robust regardless of the router's banner, prompt, or shell echo state.

## OIDs exposed

### Standard MIBs

`SNMPv2-MIB::system` (1.3.6.1.2.1.1) - sysDescr, sysObjectID (Linux),
sysUpTime, sysContact, sysName, sysLocation, sysServices.

`IF-MIB::ifTable` (1.3.6.1.2.1.2.2) and `ifXTable` (1.3.6.1.2.1.31.1.1) -
all interfaces from `/proc/net/dev` cross-referenced with `ifconfig`.
Includes ifIndex, ifDescr, ifType, ifMtu, ifPhysAddress (MAC),
ifAdminStatus, ifOperStatus, ifInOctets/ifOutOctets (Counter32) and
HC counterparts (Counter64), and per-interface drop/error counters.

`IP-MIB::ipAddrTable` (1.3.6.1.2.1.4.20) - one row per IPv4 address found
in `ifconfig`; maps IP -> ifIndex and netmask. Aliases (e.g. `br0:0`) map
to the parent interface's ifIndex.

`HOST-RESOURCES-MIB` (1.3.6.1.2.1.25) - hrSystemUptime, hrSystemNumUsers
(connected client count from bridge FDB), hrSystemProcesses, hrMemorySize,
hrStorageTable (one row for RAM + one per filesystem from `df`),
hrProcessorTable (one row per CPU, percent load computed from delta of
`/proc/stat` between polls).

`UCD-SNMP-MIB` (1.3.6.1.4.1.2021):
- `laTable` (.10.1) - 1, 5, and 15-minute load averages (string + integer).
- memory (.4) - memTotalReal, memAvailReal, memTotalFree, memBuffer, memCached.
- ssCpuRaw (.11) - User, Nice, System, Idle, Wait, Kernel, Intr (Counter32).
- `dskTable` (.9.1) - filesystem usage (dskPath, dskDevice, dskTotal,
  dskAvail, dskUsed, dskPercent).
- `diskIOTable` (.13.15.1) - per-block-device I/O from `/proc/diskstats`
  (Counter32 + Counter64). Idle ramdisks are filtered out.

### Private subtree (1.3.6.1.4.1.99999.1)

Unregistered PEN. Fine for self-hosted monitoring of your own gear.

- `.1.1.0` ddwrtBoard - `nvram get DD_BOARD` (e.g. "Asus RT-N12B").
- `.1.2.0` ddwrtModel - `nvram get model`.
- `.1.3.0` ddwrtBuild - `cat /proc/version`.

- `.2.1.1` `ddwrtTempTable` - generic temperature table with columns
  Index / Name / Source / Celsius / Raw. Probes:
  - Broadcom: `wl [-i ethN] phy_tempsense` per wireless interface.
  - Generic kernel: every `/sys/class/thermal/thermal_zone*/temp`
    (CPU, RAM, radios, audio DSP, NSS - whatever the SoC exposes).
  - Broadcom legacy: `/proc/dmu/temperature`.
  Different DD-WRT builds populate different rows; the table is
  discovery-driven so a router with N sensors gets N rows.

- `.3.1.1` `ddwrtWlClientTable` - associated wireless clients per radio.
  Columns: Index / MAC (PhysAddress) / Interface / RSSI (dBm). Tries
  Broadcom `wl assoclist` first, falls back to `iw <iface> station dump`
  for mac80211 / OpenWrt-based DD-WRT (e.g. Linksys MR7350 / Qualcomm).

- `.4.1.1` `ddwrtBrMacTable` - full bridge FDB from `brctl showmacs br0`,
  one row per MAC the router has seen. Columns:
  Index / MAC / Port / IsLocal / AgingMs / IPv4 (cross-referenced from
  `/proc/net/arp`). This is the canonical "every connected client"
  source - covers wired and wireless together.

## Cacti integration

ddwrt2snmp's standard-MIB coverage means most of Cacti's built-in templates
work out of the box once you add the device:
- "Net-SNMP - Load Average", "Net-SNMP - Memory Usage" (UCD-SNMP).
- "Host MIB - CPU Utilization", "Host MIB - Logged in Users",
  "Host MIB - Processes" (HOST-RESOURCES).
- Interface traffic via the SNMP Interface Statistics data query
  (ifTable / ifXTable).
- "Net-SNMP - Get Mounted Partitions" (dskTable).
- "Net-SNMP - Get Device I/O" (diskIOTable).

For temperatures (private OID), the simplest approach is to clone Cacti's
"SNMP - Generic OID Template" data + graph templates and point each at the
specific temperature instance you want, e.g.
`.1.3.6.1.4.1.99999.1.2.1.1.4.<N>` where N is the index from
`ddwrtTempIndex`. To label the graphs, walk
`.1.3.6.1.4.1.99999.1.2.1.1.2` first to see which sensor is at which index
(it varies by hardware: a Broadcom router exposes one radio temp, a
Qualcomm/OpenWrt router can have 7+ thermal zones for CPU, RAM, radios,
audio DSP, etc.).

## Project layout

```
ddwrt2snmp/                  package
|-- __init__.py
|-- __main__.py              entry point: python -m ddwrt2snmp
|-- ber.py                   ASN.1 BER encode/decode (INTEGER, OID, etc.)
|-- snmp.py                  SNMPv1/v2c message + PDU layer on top of BER
|-- agent.py                 UDP server loop; Get / GetNext / GetBulk
|-- cache.py                 thread-safe OID -> SNMPValue store; lex GetNext
|-- telnet.py                raw-socket telnet client; IAC; flexible login
|-- parsers.py               pure-function parsers for /proc, ifconfig, wl, iw
|-- mibs.py                  OID constants + builder functions
|-- poller.py                background thread; orchestrates poll cycle
|-- cli.py                   argparse + main()
`-- walk.py                  stdlib snmpget/snmpwalk client
ddwrt2snmp.sh / .bat         launcher
walk.sh / walk.bat           launcher for the walk client
```
