"""Background poller. Logs into DD-WRT over telnet on a persistent connection,
scrapes a wide set of values on each interval, and atomically replaces the
OID cache contents.

Failures of individual commands are tolerated — only telnet I/O errors abort
the poll and trigger a reconnect. After N consecutive failed polls the cache
is flushed to a clearly-marked UNREACHABLE state so stale data doesn't keep
flowing to monitors.
"""

import logging
import re
import threading
import time
from datetime import datetime, timezone

from . import mibs, parsers, snmp
from .telnet import TelnetClient, TelnetError

log = logging.getLogger(__name__)


class Poller(threading.Thread):
    def __init__(self, host, port, user, password, cache, interval=60.0,
                 flush_after_failures=3):
        super().__init__(name="ddwrt-poller", daemon=True)
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.cache = cache
        self.interval = float(interval)
        self.flush_after_failures = int(flush_after_failures)
        self._stop = threading.Event()
        self._client = None
        self._prev_cpu_total = None     # for CPU% delta
        self._consecutive_failures = 0
        self._flushed = False           # True once we've flushed for the current outage

    def stop(self):
        self._stop.set()
        if self._client is not None:
            try:
                self._client.close()
            except OSError:
                pass

    def run(self):
        backoff = 1.0
        while not self._stop.is_set():
            try:
                if self._client is None:
                    self._connect()
                self._poll_once()
                backoff = 1.0
                self._consecutive_failures = 0
                self._flushed = False
            except TelnetError as e:
                self._on_failure(reason=str(e))
                self._drop_client()
                if self._stop.wait(backoff):
                    return
                backoff = min(backoff * 2, self.interval)
                continue
            except Exception:
                log.exception("unexpected poller error; reconnecting")
                self._on_failure(reason="unexpected poller error")
                self._drop_client()
                if self._stop.wait(backoff):
                    return
                backoff = min(backoff * 2, self.interval)
                continue

            if self._stop.wait(self.interval):
                return

    def _on_failure(self, reason):
        self._consecutive_failures += 1
        log.warning("poll failed (#%d): %s",
                    self._consecutive_failures, reason)
        if (not self._flushed
                and self.flush_after_failures > 0
                and self._consecutive_failures >= self.flush_after_failures):
            self._flush_cache_unreachable()
            self._flushed = True

    def _flush_cache_unreachable(self):
        """Replace the cache with a minimal unreachable-marker so monitors
        stop ingesting stale data. Keeps SNMP responsive (system group still
        answers) but every other table goes empty."""
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
        msg = (f"DD-WRT (via ddwrt2snmp) -- UNREACHABLE at "
               f"{self.host}:{self.port} since {ts} "
               f"({self._consecutive_failures} consecutive failed polls)")
        self.cache.bulk_replace({
            mibs.SYS_DESCR:     snmp.octet_string(msg),
            mibs.SYS_OBJECT_ID: snmp.oid(mibs.LINUX_SYS_OBJECT_ID),
            mibs.SYS_UPTIME:    snmp.timeticks(0),
            mibs.SYS_CONTACT:   snmp.octet_string(""),
            mibs.SYS_NAME:      snmp.octet_string(""),
            mibs.SYS_LOCATION:  snmp.octet_string(""),
            mibs.SYS_SERVICES:  snmp.integer(mibs.SYS_SERVICES_DDWRT),
        })
        log.error("cache flushed: %d consecutive failures; SNMP now reports "
                  "UNREACHABLE until next successful poll",
                  self._consecutive_failures)

    def _connect(self):
        log.info("connecting to DD-WRT at %s:%d", self.host, self.port)
        client = TelnetClient(self.host, self.port)
        client.connect()
        client.login(self.user, self.password)
        self._client = client

    def _drop_client(self):
        if self._client is not None:
            try:
                self._client.close()
            except OSError:
                pass
            self._client = None

    # --- run/parse helpers ---

    def _try(self, cmd, timeout=8.0, default=""):
        """Run a command. Return stdout text on success; `default` on non-zero
        exit. Re-raise TelnetError so the outer loop can reconnect."""
        out, ec = self._client.run(cmd, timeout=timeout)
        if ec != 0:
            return default
        return out

    # --- the actual scrape ---

    def _poll_once(self):
        # ----- core data -----
        uname        = self._try("uname -a", 8.0).strip()
        version_text = self._try("cat /proc/version", 5.0).strip()
        proc_uptime  = self._try("cat /proc/uptime", 5.0).strip()
        loadavg_txt  = self._try("cat /proc/loadavg", 5.0).strip()
        proc_stat    = self._try("cat /proc/stat", 5.0)
        meminfo_txt  = self._try("cat /proc/meminfo", 5.0)
        net_dev_txt  = self._try("cat /proc/net/dev", 5.0)
        ifconfig_txt = self._try("ifconfig", 8.0)
        wl_dev_txt   = self._try("cat /proc/net/wireless 2>/dev/null", 5.0)
        arp_txt      = self._try("cat /proc/net/arp", 5.0)
        df_txt       = self._try("df", 5.0)
        brctl_txt    = self._try("brctl showmacs br0 2>/dev/null", 8.0)
        diskstats_txt = self._try("cat /proc/diskstats 2>/dev/null", 5.0)

        hostname     = self._try("cat /proc/sys/kernel/hostname", 5.0).strip()
        router_name  = self._try("nvram get router_name", 5.0).strip()
        contact      = self._try("nvram get router_contact 2>/dev/null", 5.0).strip()
        location     = self._try("nvram get router_location 2>/dev/null", 5.0).strip()
        board        = self._try("nvram get DD_BOARD 2>/dev/null", 5.0).strip()
        model        = self._try("nvram get model 2>/dev/null", 5.0).strip()

        # ----- parse -----
        net_dev    = parsers.parse_proc_net_dev(net_dev_txt)
        ifc        = parsers.parse_ifconfig(ifconfig_txt)
        wl_ifaces  = parsers.parse_proc_net_wireless(wl_dev_txt)
        meminfo    = parsers.parse_meminfo(meminfo_txt)
        loadavg    = parsers.parse_loadavg(loadavg_txt)
        stat       = parsers.parse_proc_stat(proc_stat)
        df_entries = parsers.parse_df(df_txt)
        bridge     = parsers.parse_brctl_showmacs(brctl_txt)
        arp        = parsers.parse_proc_net_arp(arp_txt)
        ut         = parsers.parse_uptime(proc_uptime)
        diskstats  = parsers.parse_proc_diskstats(diskstats_txt)
        # Filter out the 16 always-idle ramdisk minor nodes; keep mtdblock* etc.
        diskstats  = [d for d in diskstats
                      if not (d["name"].startswith("ram")
                              and d["reads_done"] == 0
                              and d["writes_done"] == 0)]

        # ----- temperature probe (every plausible source) -----
        temps = self._probe_temperatures(wl_ifaces)

        # ----- wireless clients per radio -----
        wl_clients = self._probe_wireless_clients(wl_ifaces)

        # ----- derived values -----
        uptime_secs = ut["seconds"] if ut else 0.0

        # CPU% per CPU (delta against previous /proc/stat)
        cpu_loads = self._compute_cpu_loads(stat)
        self._prev_cpu_total = stat["cpu_total"]

        # Connected client count: bridge MAC entries that are not local (ports).
        num_clients = sum(1 for e in bridge if not e["is_local"])

        num_procs = loadavg["procs_total"] if loadavg else 0

        # ARP -> IP-by-MAC map for enriching bridge entries
        ip_by_mac = {a["mac"]: a["ip"] for a in arp}

        # ----- assemble OID -> SNMPValue dict -----
        update = {}
        update.update(mibs.build_system_group(
            uname=uname,
            name=router_name or hostname,
            contact=contact,
            location=location,
            uptime_centi=int(uptime_secs * 100),
        ))
        update.update(mibs.build_if_table(net_dev, ifc, wl_ifaces))
        update.update(mibs.build_ip_addr_table(ifc, net_dev))
        update.update(mibs.build_load_table(loadavg))
        update.update(mibs.build_ucd_memory(meminfo))
        update.update(mibs.build_ucd_cpu_raw(stat["cpu_total"]))
        update.update(mibs.build_ucd_disk_table(df_entries))
        update.update(mibs.build_ucd_diskio_table(diskstats))
        update.update(mibs.build_host_resources(
            uptime_secs=uptime_secs,
            num_users=num_clients,
            num_procs=num_procs,
            meminfo=meminfo,
            df_entries=df_entries,
            cpu_loads=cpu_loads or [0],
        ))
        update.update(mibs.build_ddwrt_router(board, model, version_text))
        update.update(mibs.build_temperatures(temps))
        update.update(mibs.build_wireless_clients(wl_clients))
        update.update(mibs.build_bridge_macs(bridge, ip_by_mac))

        # Atomic swap.
        self.cache.bulk_replace(update)
        log.info("poll OK: %d OIDs (ifs=%d wl=%d clients=%d temps=%d fs=%d)",
                 len(update), len(net_dev), len(wl_ifaces),
                 num_clients, len(temps), len(df_entries))

    # --- probes ---

    def _probe_temperatures(self, wireless_ifaces):
        """Try every potential source. Return list of {name, source, celsius, raw}."""
        out = []

        # 1) wl phy_tempsense per wireless interface (Broadcom)
        for i, wif in enumerate(wireless_ifaces):
            text, ec = self._client.run(
                f"wl -i {wif} phy_tempsense 2>/dev/null", timeout=5.0)
            if ec == 0:
                v = parsers.parse_wl_temp(text)
                if v is not None:
                    out.append({
                        "name":    f"Radio {i} ({wif})",
                        "source":  f"wl -i {wif} phy_tempsense",
                        "celsius": v,  # raw is already in degrees C on this firmware
                        "raw":     v,
                    })

        # 2) /sys/class/thermal/thermal_zone*/temp (generic kernel thermal zones)
        # Use shell glob expansion via `echo` to dodge `ls` aliases that emit
        # ANSI color codes; busybox echo always returns plain text.
        zones_text, ec = self._client.run(
            "cd /sys/class/thermal 2>/dev/null && echo thermal_zone*",
            timeout=5.0)
        if ec == 0:
            for zone in zones_text.split():
                # If the glob didn't expand (no zones) shell returns the literal
                # pattern "thermal_zone*" — skip that.
                if zone == "thermal_zone*" or not zone.startswith("thermal_zone"):
                    continue
                val_text, ec2 = self._client.run(
                    f"cat /sys/class/thermal/{zone}/temp 2>/dev/null", timeout=5.0)
                if ec2 != 0:
                    continue
                m = re.match(r"\s*(-?\d+)", val_text)
                if not m:
                    continue
                raw = int(m.group(1))
                # Kernel reports millidegrees C when |value| > 200.
                celsius = raw // 1000 if abs(raw) >= 200 else raw
                type_text, _ = self._client.run(
                    f"cat /sys/class/thermal/{zone}/type 2>/dev/null", timeout=3.0)
                label = type_text.strip() or zone
                out.append({
                    "name":    f"{label} ({zone})",
                    "source":  f"/sys/class/thermal/{zone}/temp",
                    "celsius": celsius,
                    "raw":     raw,
                })

        # 3) /proc/dmu/temperature (Broadcom CPU temp on some platforms)
        dmu_text, ec = self._client.run(
            "cat /proc/dmu/temperature 2>/dev/null", timeout=3.0)
        if ec == 0 and dmu_text.strip():
            m = re.search(r"(-?\d+)", dmu_text)
            if m:
                raw = int(m.group(1))
                out.append({
                    "name":    "CPU (DMU)",
                    "source":  "/proc/dmu/temperature",
                    "celsius": raw,
                    "raw":     raw,
                })

        return out

    def _probe_wireless_clients(self, wireless_ifaces):
        """Per radio: associated stations with signal/RSSI.
        Tries Broadcom `wl` first; falls back to `iw` for mac80211 platforms
        (Qualcomm, OpenWrt-based DD-WRT, etc.)."""
        clients = []
        for wif in wireless_ifaces:
            # Broadcom path
            assoc_text, ec = self._client.run(
                f"wl -i {wif} assoclist 2>/dev/null", timeout=5.0)
            if ec == 0 and assoc_text.strip():
                for mac in parsers.parse_wl_assoclist(assoc_text):
                    rssi = None
                    rssi_text, ec2 = self._client.run(
                        f"wl -i {wif} rssi {mac} 2>/dev/null", timeout=5.0)
                    if ec2 == 0:
                        rssi = parsers.parse_wl_rssi(rssi_text)
                    clients.append({"mac": mac, "iface": wif, "rssi": rssi})
                continue

            # mac80211 / iw fallback
            iw_text, ec = self._client.run(
                f"iw {wif} station dump 2>/dev/null", timeout=5.0)
            if ec == 0 and iw_text.strip():
                for sta in parsers.parse_iw_station_dump(iw_text):
                    clients.append({
                        "mac":   sta["mac"],
                        "iface": wif,
                        "rssi":  sta.get("signal"),
                    })
        return clients

    def _compute_cpu_loads(self, stat):
        """Return list of CPU load percentages, one per CPU. Returns [0..]
        on the first poll (no delta yet)."""
        loads = []
        for cpu in stat["cpus"]:
            prev = self._prev_cpu_total
            if (prev is None or len(prev) != len(cpu)
                    or len(cpu) < 4):
                loads.append(0)
                continue
            idle_delta  = cpu[3] - prev[3]
            total_delta = sum(cpu) - sum(prev)
            if total_delta <= 0:
                loads.append(0)
            else:
                loads.append(int((1 - idle_delta / total_delta) * 100))
        return loads
