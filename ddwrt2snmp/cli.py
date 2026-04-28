"""Command-line entry point."""

import argparse
import logging
import sys

from . import snmp
from .agent import Agent
from .cache import OIDCache
from .mibs import seed_initial
from .poller import Poller


def parse_endpoint(s, default_port):
    if ":" in s:
        host, port = s.rsplit(":", 1)
        try:
            return host, int(port)
        except ValueError:
            raise argparse.ArgumentTypeError(f"invalid port in {s!r}")
    return s, default_port


def build_parser():
    p = argparse.ArgumentParser(
        prog="ddwrt2snmp",
        description="Bridge DD-WRT (telnet) to SNMP. Stdlib-only, hand-rolled.",
    )
    p.add_argument("--target", required=True, metavar="HOST[:PORT]",
                   help="DD-WRT telnet target (default port 23).")
    p.add_argument("--user", required=True, help="Telnet username.")
    p.add_argument("--password", required=True, help="Telnet password.")
    p.add_argument("--bind", default="127.0.0.1:161", metavar="HOST[:PORT]",
                   help="SNMP listen address (default 127.0.0.1:161). "
                        "Use 0.0.0.0 to listen on all interfaces. "
                        "Pick a high port (e.g. 1161) to avoid needing root/admin.")
    p.add_argument("--snmp-version", choices=["1", "2c"], default="2c",
                   help="SNMP version to serve (default 2c).")
    p.add_argument("--community", default="public",
                   help="SNMP community string (default 'public').")
    p.add_argument("--poll-interval", type=int, default=60, metavar="SECONDS",
                   help="Seconds between telnet polls (default 60).")
    p.add_argument("--flush-after-failures", type=int, default=3, metavar="N",
                   help="Flush cache to UNREACHABLE marker after N consecutive "
                        "failed polls (default 3, set 0 to disable).")
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    log = logging.getLogger("ddwrt2snmp")

    target_host, target_port = parse_endpoint(args.target, 23)
    bind_host, bind_port = parse_endpoint(args.bind, 161)
    version = snmp.VERSION_V1 if args.snmp_version == "1" else snmp.VERSION_V2C

    cache = OIDCache()
    seed_initial(cache)

    agent = Agent(bind_host, bind_port, args.community, version, cache)
    try:
        agent.start()
    except OSError as e:
        print(f"failed to bind {bind_host}:{bind_port}: {e}", file=sys.stderr)
        if bind_port < 1024:
            print("  (port < 1024 typically requires root/admin privileges)",
                  file=sys.stderr)
        return 1

    poller = Poller(target_host, target_port, args.user, args.password,
                    cache, interval=args.poll_interval,
                    flush_after_failures=args.flush_after_failures)
    log.info("DD-WRT target: telnet %s:%d as %r (poll every %ds)",
             target_host, target_port, args.user, args.poll_interval)
    poller.start()

    try:
        agent.serve_forever()
    except KeyboardInterrupt:
        log.info("shutting down")
    finally:
        poller.stop()
        agent.stop()
    return 0
