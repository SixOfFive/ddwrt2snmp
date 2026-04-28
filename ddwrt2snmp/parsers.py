"""Pure-function parsers for the text DD-WRT exposes via shell commands.

Every parser takes the raw stdout text and returns plain Python data structures
(dicts/lists/tuples) — no SNMP types. The OID layer in mibs.py turns these into
varbinds. Keeping the boundary clean means each parser is unit-testable.
"""

import re


# --- /proc/net/dev ----------------------------------------------------------

def parse_proc_net_dev(text):
    """Parse /proc/net/dev. Returns list of dicts in the order they appear."""
    out = []
    lines = text.splitlines()
    # First two lines are headers: "Inter-|..." and " face |..."
    for line in lines[2:]:
        if ":" not in line:
            continue
        name_part, stats_part = line.split(":", 1)
        name = name_part.strip()
        stats = stats_part.split()
        if len(stats) < 16:
            continue
        out.append({
            "name":         name,
            "rx_bytes":     int(stats[0]),
            "rx_packets":   int(stats[1]),
            "rx_errs":      int(stats[2]),
            "rx_drop":      int(stats[3]),
            "rx_fifo":      int(stats[4]),
            "rx_frame":     int(stats[5]),
            "rx_compressed": int(stats[6]),
            "rx_multicast": int(stats[7]),
            "tx_bytes":     int(stats[8]),
            "tx_packets":   int(stats[9]),
            "tx_errs":      int(stats[10]),
            "tx_drop":      int(stats[11]),
            "tx_fifo":      int(stats[12]),
            "tx_colls":     int(stats[13]),
            "tx_carrier":   int(stats[14]),
            "tx_compressed": int(stats[15]),
        })
    return out


# --- ifconfig ---------------------------------------------------------------

_IFCONFIG_FLAG_NAMES = {
    "UP", "DOWN", "BROADCAST", "RUNNING", "MULTICAST", "NOARP",
    "LOOPBACK", "POINTOPOINT", "PROMISC", "NOTRAILERS", "ALLMULTI",
    "SIMPLEX", "DYNAMIC",
}

_FLAG_RE = re.compile(
    r"^\s*((?:[A-Z]+(?:\s+[A-Z]+)*?))\s+MTU:", re.MULTILINE)


def parse_ifconfig(text):
    """Parse busybox ifconfig output. Returns dict: name -> info dict."""
    # Split blocks: a new interface starts at column 0.
    blocks = re.split(r"\n(?=\S)", text)
    out = {}
    for block in blocks:
        block = block.rstrip()
        if not block:
            continue
        first = block.split("\n", 1)[0]
        name = first.split()[0]
        info = {
            "encap": None, "mac": None, "mtu": None,
            "ipv4": None, "mask": None, "bcast": None,
            "flags": set(),
            "rx_bytes": None, "tx_bytes": None,
            "rx_packets": None, "tx_packets": None,
            "rx_errs": None, "tx_errs": None,
            "rx_drop": None, "tx_drop": None,
        }
        m = re.search(r"Link encap:(\S+(?:\s\S+)?)", block)
        if m:
            info["encap"] = m.group(1).strip()
        m = re.search(r"HWaddr ([0-9A-Fa-f:]+)", block)
        if m:
            info["mac"] = m.group(1).upper()
        m = re.search(r"MTU:(\d+)", block)
        if m:
            info["mtu"] = int(m.group(1))
        m = re.search(r"inet addr:(\S+)", block)
        if m:
            info["ipv4"] = m.group(1)
        m = re.search(r"Mask:(\S+)", block)
        if m:
            info["mask"] = m.group(1)
        m = re.search(r"Bcast:(\S+)", block)
        if m:
            info["bcast"] = m.group(1)
        # Flag line ends with "MTU:..." — pick out the all-caps tokens before it.
        m = _FLAG_RE.search(block)
        if m:
            info["flags"] = {t for t in m.group(1).split()
                             if t in _IFCONFIG_FLAG_NAMES}
        out[name] = info
    return out


# --- /proc/net/wireless -----------------------------------------------------

def parse_proc_net_wireless(text):
    """Returns list of wireless interface names."""
    names = []
    for line in text.splitlines():
        m = re.match(r"\s*(\S+):\s+\d+", line)
        if m:
            names.append(m.group(1))
    return names


# --- /proc/meminfo ----------------------------------------------------------

def parse_meminfo(text):
    """Returns dict mapping lowercase field name to value in kB."""
    out = {}
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z_]+):\s*(\d+)\s*(kB)?", line)
        if not m:
            continue
        out[m.group(1).lower()] = int(m.group(2))
    return out


# --- /proc/loadavg ----------------------------------------------------------

def parse_loadavg(text):
    parts = text.split()
    if len(parts) < 5:
        return None
    try:
        load1, load5, load15 = float(parts[0]), float(parts[1]), float(parts[2])
    except ValueError:
        return None
    running, _, total = parts[3].partition("/")
    try:
        running, total = int(running), int(total or "0")
        last_pid = int(parts[4])
    except ValueError:
        return None
    return {
        "load1": load1, "load5": load5, "load15": load15,
        "procs_running": running, "procs_total": total, "last_pid": last_pid,
    }


# --- /proc/stat -------------------------------------------------------------

def parse_proc_stat(text):
    """Returns {'cpu_total': [...counters...], 'cpus': [[...], ...]}."""
    out = {"cpu_total": None, "cpus": []}
    for line in text.splitlines():
        if line.startswith("cpu "):
            parts = line.split()
            try:
                out["cpu_total"] = [int(x) for x in parts[1:]]
            except ValueError:
                pass
        elif line.startswith("cpu") and len(line) > 3 and line[3].isdigit():
            parts = line.split()
            try:
                out["cpus"].append([int(x) for x in parts[1:]])
            except ValueError:
                pass
    return out


# --- /proc/uptime -----------------------------------------------------------

def parse_uptime(text):
    parts = text.split()
    if len(parts) < 1:
        return None
    try:
        return {"seconds": float(parts[0]),
                "idle": float(parts[1]) if len(parts) > 1 else 0.0}
    except ValueError:
        return None


# --- df ---------------------------------------------------------------------

def parse_df(text):
    """Parse `df` (1K-blocks). Returns list of mount entries."""
    lines = text.splitlines()
    out = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        try:
            blocks_1k = int(parts[1])
            used_1k = int(parts[2])
            avail_1k = int(parts[3])
        except ValueError:
            continue
        out.append({
            "fs":       parts[0],
            "blocks_1k": blocks_1k,
            "used_1k":  used_1k,
            "avail_1k": avail_1k,
            "use_pct":  parts[4],
            "mount":    parts[5],
        })
    return out


# --- brctl showmacs ---------------------------------------------------------

def parse_brctl_showmacs(text):
    out = []
    for line in text.splitlines()[1:]:  # skip header
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            port = int(parts[0])
            aging = float(parts[3])
        except ValueError:
            continue
        out.append({
            "port":      port,
            "mac":       parts[1].upper(),
            "is_local":  parts[2].lower() == "yes",
            "aging_sec": aging,
        })
    return out


# --- wl assoclist -----------------------------------------------------------

def parse_wl_assoclist(text):
    macs = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "assoclist":
            macs.append(parts[1].upper())
    return macs


# --- wl phy_tempsense -------------------------------------------------------

def parse_wl_temp(text):
    """Broadcom `wl phy_tempsense` — returns int (degrees C, raw) or None."""
    m = re.match(r"\s*(-?\d+)", text or "")
    if not m:
        return None
    return int(m.group(1))


# --- iw dev / iw station dump (mac80211 / non-Broadcom platforms) -----------

def parse_iw_dev(text):
    """Returns list of interface names from `iw dev` output."""
    ifaces = []
    for line in text.splitlines():
        m = re.match(r"\s*Interface\s+(\S+)", line)
        if m:
            ifaces.append(m.group(1))
    return ifaces


def parse_iw_station_dump(text):
    """Returns list of {mac, signal, rx_bytes, tx_bytes} from
    `iw <iface> station dump`. signal is dBm (int) or None."""
    out = []
    cur = None
    for line in text.splitlines():
        m = re.match(r"\s*Station\s+([0-9a-fA-F:]{17})", line)
        if m:
            if cur is not None:
                out.append(cur)
            cur = {"mac": m.group(1).upper(), "signal": None,
                   "rx_bytes": None, "tx_bytes": None}
            continue
        if cur is None:
            continue
        m = re.match(r"\s*signal:\s*(-?\d+)", line)
        if m:
            cur["signal"] = int(m.group(1))
            continue
        m = re.match(r"\s*rx bytes:\s*(\d+)", line)
        if m:
            cur["rx_bytes"] = int(m.group(1))
            continue
        m = re.match(r"\s*tx bytes:\s*(\d+)", line)
        if m:
            cur["tx_bytes"] = int(m.group(1))
            continue
    if cur is not None:
        out.append(cur)
    return out


# --- wl rssi ----------------------------------------------------------------

def parse_wl_rssi(text):
    m = re.match(r"\s*(-?\d+)", text or "")
    if not m:
        return None
    return int(m.group(1))


# --- /proc/diskstats --------------------------------------------------------

def parse_proc_diskstats(text):
    """Returns list of dicts in /proc/diskstats order."""
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 14:
            continue
        try:
            out.append({
                "major":               int(parts[0]),
                "minor":               int(parts[1]),
                "name":                parts[2],
                "reads_done":          int(parts[3]),
                "reads_merged":        int(parts[4]),
                "sectors_read":        int(parts[5]),
                "time_reading_ms":     int(parts[6]),
                "writes_done":         int(parts[7]),
                "writes_merged":       int(parts[8]),
                "sectors_written":     int(parts[9]),
                "time_writing_ms":     int(parts[10]),
                "ios_in_progress":     int(parts[11]),
                "time_io_ms":          int(parts[12]),
                "weighted_time_io_ms": int(parts[13]),
            })
        except ValueError:
            continue
    return out


# --- /proc/net/arp ----------------------------------------------------------

def parse_proc_net_arp(text):
    """Returns list of {ip, hw_type, flags, mac, mask, device}."""
    out = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        # Skip incomplete (00:00:00:00:00:00) entries
        mac = parts[3].upper()
        if mac == "00:00:00:00:00:00":
            continue
        out.append({
            "ip":     parts[0],
            "hw":     parts[1],
            "flags":  parts[2],
            "mac":    mac,
            "mask":   parts[4],
            "device": parts[5],
        })
    return out


# --- helpers ----------------------------------------------------------------

def mac_str_to_bytes(mac):
    """'40:B0:76:97:2B:48' -> b'\\x40\\xb0\\x76\\x97\\x2b\\x48'."""
    return bytes(int(p, 16) for p in mac.split(":"))


def ipv4_str_to_bytes(ip):
    return bytes(int(p) for p in ip.split("."))
