"""OID definitions and table builders.

Each `build_*` function takes parsed data (plain dicts/lists from parsers.py)
and returns a flat {oid_tuple: SNMPValue} mapping that the poller merges into
the cache. Keeping the shape flat makes lex-ordered GetNext/GetBulk traversal
trivial for the agent.

The DDWRT private subtree lives under .1.3.6.1.4.1.99999.1. This is an
unregistered (squatted) PEN — fine for self-hosted monitoring of your own
gear; do not collide with whoever IANA may eventually assign 99999 to.
"""

import time

from . import snmp
from . import parsers as P


# === RFC1213-MIB :: system group ===========================================

SYS_DESCR     = (1, 3, 6, 1, 2, 1, 1, 1, 0)
SYS_OBJECT_ID = (1, 3, 6, 1, 2, 1, 1, 2, 0)
SYS_UPTIME    = (1, 3, 6, 1, 2, 1, 1, 3, 0)
SYS_CONTACT   = (1, 3, 6, 1, 2, 1, 1, 4, 0)
SYS_NAME      = (1, 3, 6, 1, 2, 1, 1, 5, 0)
SYS_LOCATION  = (1, 3, 6, 1, 2, 1, 1, 6, 0)
SYS_SERVICES  = (1, 3, 6, 1, 2, 1, 1, 7, 0)

LINUX_SYS_OBJECT_ID = (1, 3, 6, 1, 4, 1, 8072, 3, 2, 10)

# bit sum: network(4) + transport(8) + application(64) = 76
SYS_SERVICES_DDWRT = 76


# === IF-MIB ================================================================

IF_NUMBER  = (1, 3, 6, 1, 2, 1, 2, 1, 0)
IF_ENTRY   = (1, 3, 6, 1, 2, 1, 2, 2, 1)
IFX_ENTRY  = (1, 3, 6, 1, 2, 1, 31, 1, 1, 1)


# === IP-MIB::ipAddrTable ===================================================

IP_ADDR_ENTRY = (1, 3, 6, 1, 2, 1, 4, 20, 1)

IF_TYPE_OTHER       = 1
IF_TYPE_ETHERNET    = 6
IF_TYPE_LOOPBACK    = 24
IF_TYPE_IEEE80211   = 71

IF_ADMIN_UP, IF_ADMIN_DOWN = 1, 2
IF_OPER_UP,  IF_OPER_DOWN  = 1, 2


# === HOST-RESOURCES-MIB ====================================================

HR_SYSTEM_UPTIME    = (1, 3, 6, 1, 2, 1, 25, 1, 1, 0)
HR_SYSTEM_DATE      = (1, 3, 6, 1, 2, 1, 25, 1, 2, 0)
HR_SYSTEM_NUM_USERS = (1, 3, 6, 1, 2, 1, 25, 1, 5, 0)
HR_SYSTEM_PROCESSES = (1, 3, 6, 1, 2, 1, 25, 1, 6, 0)
HR_MEMORY_SIZE      = (1, 3, 6, 1, 2, 1, 25, 2, 2, 0)
HR_STORAGE_ENTRY    = (1, 3, 6, 1, 2, 1, 25, 2, 3, 1)
HR_PROCESSOR_ENTRY  = (1, 3, 6, 1, 2, 1, 25, 3, 3, 1)

HR_STORAGE_RAM        = (1, 3, 6, 1, 2, 1, 25, 2, 1, 2)
HR_STORAGE_VIRTUAL    = (1, 3, 6, 1, 2, 1, 25, 2, 1, 3)
HR_STORAGE_FIXED_DISK = (1, 3, 6, 1, 2, 1, 25, 2, 1, 4)
HR_STORAGE_FLASH      = (1, 3, 6, 1, 2, 1, 25, 2, 1, 9)


# === UCD-SNMP-MIB ==========================================================

_UCD = (1, 3, 6, 1, 4, 1, 2021)

LA_ENTRY          = _UCD + (10, 1)
DSK_ENTRY         = _UCD + (9, 1)   # dskTable: filesystem usage
DISKIO_ENTRY      = _UCD + (13, 15, 1)  # diskIOTable: per-block-device I/O

MEM_INDEX         = _UCD + (4, 1, 0)
MEM_TOTAL_SWAP    = _UCD + (4, 3, 0)
MEM_AVAIL_SWAP    = _UCD + (4, 4, 0)
MEM_TOTAL_REAL    = _UCD + (4, 5, 0)
MEM_AVAIL_REAL    = _UCD + (4, 6, 0)
MEM_TOTAL_FREE    = _UCD + (4, 11, 0)
MEM_BUFFER        = _UCD + (4, 14, 0)
MEM_CACHED        = _UCD + (4, 15, 0)

SS_CPU_RAW_USER   = _UCD + (11, 50, 0)
SS_CPU_RAW_NICE   = _UCD + (11, 51, 0)
SS_CPU_RAW_SYSTEM = _UCD + (11, 52, 0)
SS_CPU_RAW_IDLE   = _UCD + (11, 53, 0)
SS_CPU_RAW_WAIT   = _UCD + (11, 54, 0)
SS_CPU_RAW_KERNEL = _UCD + (11, 55, 0)
SS_CPU_RAW_INTR   = _UCD + (11, 56, 0)


# === Private DDWRT-MIB (unregistered PEN; see module docstring) ============

DDWRT = (1, 3, 6, 1, 4, 1, 99999, 1)

# .1 router identity ---------------------------------------------------------
DDWRT_BOARD = DDWRT + (1, 1, 0)  # OCTET STRING (e.g. "Asus RT-N12B")
DDWRT_MODEL = DDWRT + (1, 2, 0)  # OCTET STRING (nvram model, may be empty)
DDWRT_BUILD = DDWRT + (1, 3, 0)  # OCTET STRING (kernel/build version)

# .2 generic temperature table ----------------------------------------------
# Sources include radio temps (wl phy_tempsense), CPU/board temps from
# /sys/class/thermal, /proc/dmu/temperature, etc. — anything probeable.
# Columns: 1=Index, 2=Name, 3=Source, 4=Celsius, 5=Raw
DDWRT_TEMP_ENTRY = DDWRT + (2, 1, 1)

# .3 wireless client table ---------------------------------------------------
# Columns: 1=Index, 2=MAC (PhysAddress), 3=Interface, 4=RSSI (dBm)
DDWRT_WLCLIENT_ENTRY = DDWRT + (3, 1, 1)

# .4 bridge MAC FDB (every connected client, wired+wireless) ----------------
# Columns: 1=Index, 2=MAC, 3=Port, 4=IsLocal (1=true,2=false), 5=AgingMs, 6=IPv4
DDWRT_BRMAC_ENTRY = DDWRT + (4, 1, 1)


# === seed_initial (placeholder until first poll) ===========================

def seed_initial(cache):
    proc_uptime_centiseconds = int(time.monotonic() * 100)
    cache.bulk_update({
        SYS_DESCR:     snmp.octet_string("DD-WRT (via ddwrt2snmp) -- not yet polled"),
        SYS_OBJECT_ID: snmp.oid(LINUX_SYS_OBJECT_ID),
        SYS_UPTIME:    snmp.timeticks(proc_uptime_centiseconds),
        SYS_CONTACT:   snmp.octet_string(""),
        SYS_NAME:      snmp.octet_string(""),
        SYS_LOCATION:  snmp.octet_string(""),
        SYS_SERVICES:  snmp.integer(SYS_SERVICES_DDWRT),
    })


# === BUILDERS ==============================================================
#
# Each builder takes parsed inputs and returns {oid_tuple: SNMPValue}.
# The poller merges all builder outputs and calls cache.bulk_replace().

def build_system_group(uname, name, contact, location, uptime_centi):
    return {
        SYS_DESCR:     snmp.octet_string(uname or "DD-WRT"),
        SYS_OBJECT_ID: snmp.oid(LINUX_SYS_OBJECT_ID),
        SYS_UPTIME:    snmp.timeticks(uptime_centi & 0xFFFFFFFF),
        SYS_CONTACT:   snmp.octet_string(contact or ""),
        SYS_NAME:      snmp.octet_string(name or ""),
        SYS_LOCATION:  snmp.octet_string(location or ""),
        SYS_SERVICES:  snmp.integer(SYS_SERVICES_DDWRT),
    }


def _classify_iftype(name, encap, wireless_set):
    if name in wireless_set:
        return IF_TYPE_IEEE80211
    if encap and "loopback" in encap.lower():
        return IF_TYPE_LOOPBACK
    if encap and "ethernet" in encap.lower():
        return IF_TYPE_ETHERNET
    return IF_TYPE_OTHER


def build_if_table(net_dev, ifconfig_data, wireless_names):
    """net_dev: list of dicts from parse_proc_net_dev (preserves order).
    ifconfig_data: dict from parse_ifconfig.
    wireless_names: iterable of names that should be marked ieee80211.
    """
    out = {}
    out[IF_NUMBER] = snmp.integer(len(net_dev))
    wireless_set = set(wireless_names)

    for idx, ifd in enumerate(net_dev, 1):
        name = ifd["name"]
        cfg = ifconfig_data.get(name, {})
        iftype = _classify_iftype(name, cfg.get("encap"), wireless_set)
        flags = cfg.get("flags") or set()
        admin = IF_ADMIN_UP if "UP" in flags else IF_ADMIN_DOWN
        oper  = IF_OPER_UP  if "RUNNING" in flags else IF_OPER_DOWN
        mac = cfg.get("mac")
        mac_b = P.mac_str_to_bytes(mac) if mac else b""
        mtu = cfg.get("mtu") or 0

        rx_b, rx_p = ifd["rx_bytes"], ifd["rx_packets"]
        tx_b, tx_p = ifd["tx_bytes"], ifd["tx_packets"]
        rx_mc      = ifd["rx_multicast"]
        # Approximations: kernel doesn't split ucast/mcast/bcast on the rx
        # side in /proc/net/dev — we have only "multicast" total.
        rx_ucast = max(0, rx_p - rx_mc)

        # ifTable row
        out[IF_ENTRY + (1,  idx)] = snmp.integer(idx)
        out[IF_ENTRY + (2,  idx)] = snmp.octet_string(name)
        out[IF_ENTRY + (3,  idx)] = snmp.integer(iftype)
        out[IF_ENTRY + (4,  idx)] = snmp.integer(mtu)
        out[IF_ENTRY + (5,  idx)] = snmp.gauge32(0)  # ifSpeed unknown
        out[IF_ENTRY + (6,  idx)] = snmp.octet_string(mac_b)
        out[IF_ENTRY + (7,  idx)] = snmp.integer(admin)
        out[IF_ENTRY + (8,  idx)] = snmp.integer(oper)
        out[IF_ENTRY + (9,  idx)] = snmp.timeticks(0)
        out[IF_ENTRY + (10, idx)] = snmp.counter32(rx_b & 0xFFFFFFFF)
        out[IF_ENTRY + (11, idx)] = snmp.counter32(rx_ucast & 0xFFFFFFFF)
        out[IF_ENTRY + (12, idx)] = snmp.counter32(rx_mc & 0xFFFFFFFF)
        out[IF_ENTRY + (13, idx)] = snmp.counter32(ifd["rx_drop"] & 0xFFFFFFFF)
        out[IF_ENTRY + (14, idx)] = snmp.counter32(ifd["rx_errs"] & 0xFFFFFFFF)
        out[IF_ENTRY + (15, idx)] = snmp.counter32(0)
        out[IF_ENTRY + (16, idx)] = snmp.counter32(tx_b & 0xFFFFFFFF)
        out[IF_ENTRY + (17, idx)] = snmp.counter32(tx_p & 0xFFFFFFFF)
        out[IF_ENTRY + (18, idx)] = snmp.counter32(0)
        out[IF_ENTRY + (19, idx)] = snmp.counter32(ifd["tx_drop"] & 0xFFFFFFFF)
        out[IF_ENTRY + (20, idx)] = snmp.counter32(ifd["tx_errs"] & 0xFFFFFFFF)
        out[IF_ENTRY + (21, idx)] = snmp.gauge32(0)
        out[IF_ENTRY + (22, idx)] = snmp.oid((0, 0))

        # ifXTable row (HC counters etc.)
        out[IFX_ENTRY + (1,  idx)] = snmp.octet_string(name)
        out[IFX_ENTRY + (2,  idx)] = snmp.counter32(rx_mc & 0xFFFFFFFF)
        out[IFX_ENTRY + (3,  idx)] = snmp.counter32(0)
        out[IFX_ENTRY + (4,  idx)] = snmp.counter32(0)
        out[IFX_ENTRY + (5,  idx)] = snmp.counter32(0)
        out[IFX_ENTRY + (6,  idx)] = snmp.counter64(rx_b)
        out[IFX_ENTRY + (7,  idx)] = snmp.counter64(rx_ucast)
        out[IFX_ENTRY + (8,  idx)] = snmp.counter64(rx_mc)
        out[IFX_ENTRY + (9,  idx)] = snmp.counter64(0)
        out[IFX_ENTRY + (10, idx)] = snmp.counter64(tx_b)
        out[IFX_ENTRY + (11, idx)] = snmp.counter64(tx_p)
        out[IFX_ENTRY + (12, idx)] = snmp.counter64(0)
        out[IFX_ENTRY + (13, idx)] = snmp.counter64(0)
        out[IFX_ENTRY + (14, idx)] = snmp.integer(2)   # trapEnable: disabled
        out[IFX_ENTRY + (15, idx)] = snmp.gauge32(0)
        out[IFX_ENTRY + (16, idx)] = snmp.integer(2)   # promiscuous: false
        out[IFX_ENTRY + (17, idx)] = snmp.integer(2)   # connectorPresent: false
        out[IFX_ENTRY + (18, idx)] = snmp.octet_string("")  # ifAlias
        out[IFX_ENTRY + (19, idx)] = snmp.timeticks(0)

    return out


def build_ucd_disk_table(df_entries):
    """UCD-SNMP-MIB::dskTable — what Cacti's "Get Mounted Partitions" walks."""
    out = {}
    for idx, fs in enumerate(df_entries, 1):
        total = fs["blocks_1k"]
        used  = fs["used_1k"]
        avail = fs["avail_1k"]
        pct = int(used * 100 / total) if total > 0 else 0
        out[DSK_ENTRY + (1,  idx)] = snmp.integer(idx)
        out[DSK_ENTRY + (2,  idx)] = snmp.octet_string(fs["mount"])
        out[DSK_ENTRY + (3,  idx)] = snmp.octet_string(fs["fs"])
        out[DSK_ENTRY + (6,  idx)] = snmp.integer(total)
        out[DSK_ENTRY + (7,  idx)] = snmp.integer(avail)
        out[DSK_ENTRY + (8,  idx)] = snmp.integer(used)
        out[DSK_ENTRY + (9,  idx)] = snmp.integer(pct)
        out[DSK_ENTRY + (10, idx)] = snmp.integer(0)   # dskPercentNode (no inode info)
    return out


def build_ip_addr_table(ifconfig_data, net_dev):
    """IP-MIB::ipAddrTable. One row per IPv4 address found in ifconfig.
    Indexed by the IP address itself (4 sub-OIDs after the column number).
    Aliases (e.g. br0:0) map back to the parent's ifIndex.
    """
    out = {}
    name_to_index = {ifd["name"]: i + 1 for i, ifd in enumerate(net_dev)}
    for name, info in ifconfig_data.items():
        ip = info.get("ipv4")
        if not ip:
            continue
        try:
            ip_arcs = tuple(int(p) for p in ip.split("."))
        except ValueError:
            continue
        if len(ip_arcs) != 4:
            continue
        # Resolve ifIndex (handle aliases like br0:0 -> br0)
        base = name.split(":", 1)[0]
        ifindex = name_to_index.get(name, name_to_index.get(base, 0))

        mask = info.get("mask") or "255.255.255.255"
        try:
            mask_bytes = bytes(int(p) for p in mask.split("."))
            if len(mask_bytes) != 4:
                mask_bytes = b"\xff\xff\xff\xff"
        except ValueError:
            mask_bytes = b"\xff\xff\xff\xff"

        ip_bytes = bytes(ip_arcs)
        out[IP_ADDR_ENTRY + (1,) + ip_arcs] = snmp.ip_address(ip_bytes)
        out[IP_ADDR_ENTRY + (2,) + ip_arcs] = snmp.integer(ifindex)
        out[IP_ADDR_ENTRY + (3,) + ip_arcs] = snmp.ip_address(mask_bytes)
        out[IP_ADDR_ENTRY + (4,) + ip_arcs] = snmp.integer(1)      # bcast LSB
        out[IP_ADDR_ENTRY + (5,) + ip_arcs] = snmp.integer(65535)  # reasm max
    return out


def build_ucd_diskio_table(diskstats):
    """UCD-DISKIO-MIB::diskIOTable. Sectors are 512 bytes per Linux convention.
    Caller can filter the input list to skip the 16 idle ram* devices."""
    SECTOR = 512
    out = {}
    for idx, d in enumerate(diskstats, 1):
        nread_64 = d["sectors_read"] * SECTOR
        nwrite_64 = d["sectors_written"] * SECTOR
        out[DISKIO_ENTRY + (1,  idx)] = snmp.integer(idx)
        out[DISKIO_ENTRY + (2,  idx)] = snmp.octet_string(d["name"])
        out[DISKIO_ENTRY + (3,  idx)] = snmp.counter32(nread_64 & 0xFFFFFFFF)
        out[DISKIO_ENTRY + (4,  idx)] = snmp.counter32(nwrite_64 & 0xFFFFFFFF)
        out[DISKIO_ENTRY + (5,  idx)] = snmp.counter32(d["reads_done"] & 0xFFFFFFFF)
        out[DISKIO_ENTRY + (6,  idx)] = snmp.counter32(d["writes_done"] & 0xFFFFFFFF)
        out[DISKIO_ENTRY + (12, idx)] = snmp.counter64(nread_64)
        out[DISKIO_ENTRY + (13, idx)] = snmp.counter64(nwrite_64)
    return out


def build_load_table(loadavg):
    out = {}
    if not loadavg:
        return out
    items = [(1, "Load-1",  loadavg["load1"]),
             (2, "Load-5",  loadavg["load5"]),
             (3, "Load-15", loadavg["load15"])]
    for idx, name, load in items:
        out[LA_ENTRY + (1, idx)] = snmp.integer(idx)
        out[LA_ENTRY + (2, idx)] = snmp.octet_string(name)
        out[LA_ENTRY + (3, idx)] = snmp.octet_string(f"{load:.2f}")
        out[LA_ENTRY + (5, idx)] = snmp.integer(int(load * 100))
    return out


def build_ucd_memory(meminfo):
    if not meminfo:
        return {}
    return {
        MEM_INDEX:      snmp.integer(0),
        MEM_TOTAL_SWAP: snmp.integer(meminfo.get("swaptotal", 0)),
        MEM_AVAIL_SWAP: snmp.integer(meminfo.get("swapfree", 0)),
        MEM_TOTAL_REAL: snmp.integer(meminfo.get("memtotal", 0)),
        MEM_AVAIL_REAL: snmp.integer(meminfo.get("memfree", 0)),
        MEM_TOTAL_FREE: snmp.integer(meminfo.get("memfree", 0)),
        MEM_BUFFER:     snmp.integer(meminfo.get("buffers", 0)),
        MEM_CACHED:     snmp.integer(meminfo.get("cached", 0)),
    }


def build_ucd_cpu_raw(cpu_total):
    if not cpu_total or len(cpu_total) < 4:
        return {}
    user, nice, system, idle = cpu_total[0:4]
    iowait  = cpu_total[4] if len(cpu_total) > 4 else 0
    irq     = cpu_total[5] if len(cpu_total) > 5 else 0
    softirq = cpu_total[6] if len(cpu_total) > 6 else 0
    return {
        SS_CPU_RAW_USER:   snmp.counter32(user & 0xFFFFFFFF),
        SS_CPU_RAW_NICE:   snmp.counter32(nice & 0xFFFFFFFF),
        SS_CPU_RAW_SYSTEM: snmp.counter32((system + irq + softirq) & 0xFFFFFFFF),
        SS_CPU_RAW_IDLE:   snmp.counter32(idle & 0xFFFFFFFF),
        SS_CPU_RAW_WAIT:   snmp.counter32(iowait & 0xFFFFFFFF),
        SS_CPU_RAW_KERNEL: snmp.counter32(system & 0xFFFFFFFF),
        SS_CPU_RAW_INTR:   snmp.counter32((irq + softirq) & 0xFFFFFFFF),
    }


def build_host_resources(uptime_secs, num_users, num_procs,
                         meminfo, df_entries, cpu_loads):
    out = {}
    out[HR_SYSTEM_UPTIME]    = snmp.timeticks(int(uptime_secs * 100) & 0xFFFFFFFF)
    out[HR_SYSTEM_NUM_USERS] = snmp.gauge32(num_users)
    out[HR_SYSTEM_PROCESSES] = snmp.gauge32(num_procs)
    if meminfo:
        out[HR_MEMORY_SIZE] = snmp.integer(meminfo.get("memtotal", 0))

    storage_idx = 1
    if meminfo:
        memtotal = meminfo.get("memtotal", 0)
        memfree  = meminfo.get("memfree", 0)
        out[HR_STORAGE_ENTRY + (1, storage_idx)] = snmp.integer(storage_idx)
        out[HR_STORAGE_ENTRY + (2, storage_idx)] = snmp.oid(HR_STORAGE_RAM)
        out[HR_STORAGE_ENTRY + (3, storage_idx)] = snmp.octet_string("Physical memory")
        out[HR_STORAGE_ENTRY + (4, storage_idx)] = snmp.integer(1024)
        out[HR_STORAGE_ENTRY + (5, storage_idx)] = snmp.integer(memtotal)
        out[HR_STORAGE_ENTRY + (6, storage_idx)] = snmp.integer(max(0, memtotal - memfree))
        out[HR_STORAGE_ENTRY + (7, storage_idx)] = snmp.counter32(0)
        storage_idx += 1
    for fs in df_entries:
        # Pick a reasonable type — most DD-WRT mounts are squashfs/ramfs/tmpfs.
        fs_lower = (fs.get("fs") or "").lower()
        mt = (fs.get("mount") or "").lower()
        if "tmpfs" in fs_lower or "ramfs" in fs_lower or mt in ("/tmp", "/dev"):
            type_oid = HR_STORAGE_RAM
        elif "jffs" in fs_lower or "mtd" in fs_lower:
            type_oid = HR_STORAGE_FLASH
        else:
            type_oid = HR_STORAGE_FIXED_DISK
        out[HR_STORAGE_ENTRY + (1, storage_idx)] = snmp.integer(storage_idx)
        out[HR_STORAGE_ENTRY + (2, storage_idx)] = snmp.oid(type_oid)
        out[HR_STORAGE_ENTRY + (3, storage_idx)] = snmp.octet_string(
            f"{fs['mount']} ({fs['fs']})")
        out[HR_STORAGE_ENTRY + (4, storage_idx)] = snmp.integer(1024)
        out[HR_STORAGE_ENTRY + (5, storage_idx)] = snmp.integer(fs["blocks_1k"])
        out[HR_STORAGE_ENTRY + (6, storage_idx)] = snmp.integer(fs["used_1k"])
        out[HR_STORAGE_ENTRY + (7, storage_idx)] = snmp.counter32(0)
        storage_idx += 1

    for cpu_idx, load_pct in enumerate(cpu_loads, 1):
        out[HR_PROCESSOR_ENTRY + (1, cpu_idx)] = snmp.oid((0, 0))
        out[HR_PROCESSOR_ENTRY + (2, cpu_idx)] = snmp.integer(max(0, min(100, int(load_pct))))
    return out


def build_ddwrt_router(board, model, build_str):
    return {
        DDWRT_BOARD: snmp.octet_string(board or ""),
        DDWRT_MODEL: snmp.octet_string(model or ""),
        DDWRT_BUILD: snmp.octet_string(build_str or ""),
    }


def build_temperatures(temp_entries):
    """temp_entries: list of {'name', 'source', 'celsius', 'raw'}."""
    out = {}
    for idx, t in enumerate(temp_entries, 1):
        out[DDWRT_TEMP_ENTRY + (1, idx)] = snmp.integer(idx)
        out[DDWRT_TEMP_ENTRY + (2, idx)] = snmp.octet_string(t["name"])
        out[DDWRT_TEMP_ENTRY + (3, idx)] = snmp.octet_string(t["source"])
        out[DDWRT_TEMP_ENTRY + (4, idx)] = snmp.integer(int(t["celsius"]))
        out[DDWRT_TEMP_ENTRY + (5, idx)] = snmp.integer(int(t["raw"]))
    return out


def build_wireless_clients(clients):
    """clients: list of {'mac', 'iface', 'rssi'}."""
    out = {}
    for idx, c in enumerate(clients, 1):
        out[DDWRT_WLCLIENT_ENTRY + (1, idx)] = snmp.integer(idx)
        out[DDWRT_WLCLIENT_ENTRY + (2, idx)] = snmp.octet_string(P.mac_str_to_bytes(c["mac"]))
        out[DDWRT_WLCLIENT_ENTRY + (3, idx)] = snmp.octet_string(c["iface"] or "")
        rssi = c.get("rssi")
        out[DDWRT_WLCLIENT_ENTRY + (4, idx)] = snmp.integer(int(rssi) if rssi is not None else 0)
    return out


def build_bridge_macs(entries, ip_by_mac=None):
    """entries: list from parse_brctl_showmacs.
    ip_by_mac: optional {MAC -> IPv4 string} from ARP for cross-reference.
    """
    out = {}
    ip_by_mac = ip_by_mac or {}
    for idx, e in enumerate(entries, 1):
        out[DDWRT_BRMAC_ENTRY + (1, idx)] = snmp.integer(idx)
        out[DDWRT_BRMAC_ENTRY + (2, idx)] = snmp.octet_string(P.mac_str_to_bytes(e["mac"]))
        out[DDWRT_BRMAC_ENTRY + (3, idx)] = snmp.integer(e["port"])
        out[DDWRT_BRMAC_ENTRY + (4, idx)] = snmp.integer(1 if e["is_local"] else 2)
        out[DDWRT_BRMAC_ENTRY + (5, idx)] = snmp.gauge32(int(e["aging_sec"] * 1000))
        out[DDWRT_BRMAC_ENTRY + (6, idx)] = snmp.octet_string(ip_by_mac.get(e["mac"], ""))
    return out
