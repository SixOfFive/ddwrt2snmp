"""Minimal snmpget / snmpwalk client built on the same BER+SNMP modules.

Run via:  python -m ddwrt2snmp.walk HOST[:PORT] OID [options]
"""

import argparse
import socket
import sys
import time

from . import ber, snmp


def parse_endpoint(s, default_port=161):
    if ":" in s:
        host, port = s.rsplit(":", 1)
        return host, int(port)
    return s, default_port


def parse_oid(s):
    s = s.strip().lstrip(".")
    return tuple(int(p) for p in s.split("."))


def format_oid(oid):
    return "." + ".".join(str(x) for x in oid)


def _is_printable(b):
    # Empty strings count as printable (display as "STRING: " not Hex-STRING).
    return all(0x20 <= c <= 0x7E or c in (0x09, 0x0A, 0x0D) for c in b)


def _format_timeticks(n):
    days, rem = divmod(n, 8640000)
    hours, rem = divmod(rem, 360000)
    mins, rem = divmod(rem, 6000)
    secs, cs = divmod(rem, 100)
    if days:
        return f"({n}) {days} days, {hours:d}:{mins:02d}:{secs:02d}.{cs:02d}"
    return f"({n}) {hours:d}:{mins:02d}:{secs:02d}.{cs:02d}"


def format_value(v):
    t = v.tag
    if t == ber.TAG_INTEGER:
        return f"INTEGER: {v.value}"
    if t == ber.TAG_OCTET_STRING:
        b = v.value
        if _is_printable(b):
            try:
                return f"STRING: {b.decode('utf-8')}"
            except UnicodeDecodeError:
                pass
        return "Hex-STRING: " + " ".join(f"{c:02X}" for c in b)
    if t == ber.TAG_NULL:
        return "Null"
    if t == ber.TAG_OID:
        return f"OID: {format_oid(v.value)}"
    if t == ber.TAG_COUNTER32:
        return f"Counter32: {v.value}"
    if t == ber.TAG_GAUGE32:
        return f"Gauge32: {v.value}"
    if t == ber.TAG_TIMETICKS:
        return f"Timeticks: {_format_timeticks(v.value)}"
    if t == ber.TAG_IPADDRESS:
        return f"IpAddress: {'.'.join(str(c) for c in v.value)}"
    if t == ber.TAG_COUNTER64:
        return f"Counter64: {v.value}"
    if t == ber.TAG_NO_SUCH_OBJECT:
        return "No Such Object available on this agent at this OID"
    if t == ber.TAG_NO_SUCH_INSTANCE:
        return "No Such Instance currently exists at this OID"
    if t == ber.TAG_END_OF_MIB_VIEW:
        return "No more variables left in this MIB View (past end of MIB tree)"
    return f"Unknown(0x{t:02x}): {v.value!r}"


def _request(sock, addr, version, community, pdu_type, request_id, varbinds,
             err_status=0, err_index=0, retries=1, timeout=2.0):
    pkt = snmp.encode_message(version, community, pdu_type, request_id,
                              err_status, err_index, varbinds)
    last_exc = None
    for _ in range(retries + 1):
        try:
            sock.settimeout(timeout)
            sock.sendto(pkt, addr)
            data, _ = sock.recvfrom(65535)
            return snmp.decode_message(data)
        except (socket.timeout, OSError) as e:
            last_exc = e
            continue
    raise TimeoutError(f"no response from {addr[0]}:{addr[1]}: {last_exc}")


def cmd_get(addr, version, community, oid_str, timeout, retries):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    oid = parse_oid(oid_str)
    rid = int(time.time()) & 0x7FFFFFFF
    try:
        resp = _request(sock, addr, version, community.encode("utf-8"),
                        snmp.PDU_GET, rid, [(oid, snmp.null())],
                        retries=retries, timeout=timeout)
    except TimeoutError as e:
        print(f"Timeout: {e}", file=sys.stderr)
        return 1
    finally:
        sock.close()
    if resp.error_status:
        print(f"Agent error: status={resp.error_status} index={resp.error_index}",
              file=sys.stderr)
        return 1
    for o, v in resp.varbinds:
        print(f"{format_oid(o)} = {format_value(v)}")
    return 0


def cmd_walk(addr, version, community, oid_str, timeout, retries, bulk):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    base = parse_oid(oid_str)
    cur = base
    rid = int(time.time()) & 0x7FFFFFFF
    try:
        while True:
            rid = (rid + 1) & 0x7FFFFFFF
            if bulk and version == snmp.VERSION_V2C:
                resp = _request(sock, addr, version, community.encode("utf-8"),
                                snmp.PDU_GETBULK, rid,
                                [(cur, snmp.null())],
                                err_status=0, err_index=bulk,
                                retries=retries, timeout=timeout)
            else:
                resp = _request(sock, addr, version, community.encode("utf-8"),
                                snmp.PDU_GETNEXT, rid,
                                [(cur, snmp.null())],
                                retries=retries, timeout=timeout)
            if resp.error_status:
                print(f"Agent error: status={resp.error_status} index={resp.error_index}",
                      file=sys.stderr)
                return 1
            for o, v in resp.varbinds:
                if v.tag == ber.TAG_END_OF_MIB_VIEW:
                    return 0
                if o[: len(base)] != base:
                    return 0  # walked out of subtree
                print(f"{format_oid(o)} = {format_value(v)}")
                cur = o
    except TimeoutError as e:
        print(f"Timeout: {e}", file=sys.stderr)
        return 1
    finally:
        sock.close()


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="ddwrt2snmp.walk",
        description="Minimal stdlib-only snmpget/snmpwalk client.",
    )
    p.add_argument("agent", metavar="HOST[:PORT]",
                   help="Agent to query (default port 161).")
    p.add_argument("oid", help="OID to query (dotted, e.g. 1.3.6.1.2.1.1).")
    p.add_argument("-c", "--community", default="public",
                   help="SNMP community (default public).")
    p.add_argument("-v", "--version", choices=["1", "2c"], default="2c",
                   help="SNMP version (default 2c).")
    p.add_argument("-t", "--timeout", type=float, default=2.0,
                   help="Per-request timeout in seconds (default 2.0).")
    p.add_argument("-r", "--retries", type=int, default=1,
                   help="Retries per request (default 1).")
    p.add_argument("--get", action="store_true",
                   help="Single GetRequest instead of walk.")
    p.add_argument("--bulk", type=int, default=0, metavar="N",
                   help="Use GetBulk with max-repetitions=N (v2c only).")
    args = p.parse_args(argv)

    addr = parse_endpoint(args.agent, 161)
    version = snmp.VERSION_V1 if args.version == "1" else snmp.VERSION_V2C
    try:
        if args.get:
            return cmd_get(addr, version, args.community, args.oid,
                           args.timeout, args.retries)
        return cmd_walk(addr, version, args.community, args.oid,
                        args.timeout, args.retries, args.bulk)
    except ber.BERError as e:
        print(f"Invalid OID: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"Argument error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
