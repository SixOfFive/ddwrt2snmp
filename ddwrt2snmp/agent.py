"""UDP SNMP agent: handles Get / GetNext / GetBulk against an OIDCache."""

import logging
import socket

from . import ber, snmp

log = logging.getLogger(__name__)


class Agent:
    def __init__(self, bind_host, bind_port, community, version, cache):
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.community = community.encode("utf-8") if isinstance(community, str) else community
        self.version = version  # snmp.VERSION_V1 or VERSION_V2C
        self.cache = cache
        self._sock = None
        self._stop = False

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.bind_host, self.bind_port))
        log.info("SNMP agent listening on %s:%d (%s, community=%r)",
                 self.bind_host, self.bind_port,
                 "v2c" if self.version == snmp.VERSION_V2C else "v1",
                 self.community.decode("utf-8", errors="replace"))

    def serve_forever(self):
        sock = self._sock
        while not self._stop:
            try:
                data, addr = sock.recvfrom(65535)
            except OSError:
                if self._stop:
                    break
                raise
            try:
                response = self.handle(data, addr)
            except Exception:
                log.exception("error handling request from %s", addr)
                continue
            if response is not None:
                try:
                    sock.sendto(response, addr)
                except OSError as e:
                    log.warning("failed sending response to %s: %s", addr, e)

    def stop(self):
        self._stop = True
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass

    # --- request dispatch ---

    _PDU_NAMES = {
        snmp.PDU_GET:     "GET",
        snmp.PDU_GETNEXT: "GETNEXT",
        snmp.PDU_GETBULK: "GETBULK",
        snmp.PDU_SET:     "SET",
    }

    def handle(self, data, addr):
        try:
            msg = snmp.decode_message(data)
        except (snmp.SNMPError, ber.BERError, IndexError) as e:
            log.warning("malformed packet from %s:%d: %s",
                        addr[0], addr[1], e)
            return None

        if msg.version != self.version:
            log.warning("version mismatch from %s:%d: got %d, want %d",
                        addr[0], addr[1], msg.version, self.version)
            return None
        if msg.community != self.community:
            log.warning("community mismatch from %s:%d: %r",
                        addr[0], addr[1], msg.community)
            return None

        pdu_name = self._PDU_NAMES.get(msg.pdu_type, f"0x{msg.pdu_type:02x}")
        first = ".".join(str(x) for x in msg.varbinds[0][0]) if msg.varbinds else "-"
        log.info("%s from %s:%d (%d vb, first=%s)",
                 pdu_name, addr[0], addr[1], len(msg.varbinds), first)

        if msg.pdu_type == snmp.PDU_GET:
            return self._handle_get(msg)
        if msg.pdu_type == snmp.PDU_GETNEXT:
            return self._handle_getnext(msg)
        if msg.pdu_type == snmp.PDU_GETBULK and msg.version == snmp.VERSION_V2C:
            return self._handle_getbulk(msg)
        if msg.pdu_type == snmp.PDU_SET:
            # Read-only agent.
            return self._error_response(msg, snmp.ERR_NO_ACCESS, 1)

        log.warning("unsupported PDU type 0x%02x from %s:%d",
                    msg.pdu_type, addr[0], addr[1])
        return None

    # --- handlers ---

    def _handle_get(self, msg):
        out = []
        for oid_val, _ in msg.varbinds:
            entry = self.cache.get(oid_val)
            if entry is None:
                if msg.version == snmp.VERSION_V1:
                    return self._error_response(msg, snmp.ERR_NO_SUCH_NAME, len(out) + 1)
                out.append((oid_val, snmp.SNMPValue(ber.TAG_NO_SUCH_INSTANCE, None)))
            else:
                out.append((oid_val, entry))
        return self._response(msg, snmp.ERR_NO_ERROR, 0, out)

    def _handle_getnext(self, msg):
        out = []
        for oid_val, _ in msg.varbinds:
            result = self.cache.get_next(oid_val)
            if result is None:
                if msg.version == snmp.VERSION_V1:
                    return self._error_response(msg, snmp.ERR_NO_SUCH_NAME, len(out) + 1)
                out.append((oid_val, snmp.SNMPValue(ber.TAG_END_OF_MIB_VIEW, None)))
            else:
                next_oid, value = result
                out.append((next_oid, value))
        return self._response(msg, snmp.ERR_NO_ERROR, 0, out)

    def _handle_getbulk(self, msg):
        # In a GetBulk PDU, error_status is non-repeaters and error_index is
        # max-repetitions. They share the encoding slots.
        non_repeaters = max(0, msg.error_status)
        max_repetitions = max(0, msg.error_index)
        n = len(msg.varbinds)
        nr = min(non_repeaters, n)

        out = []
        for i in range(nr):
            oid_val, _ = msg.varbinds[i]
            result = self.cache.get_next(oid_val)
            if result is None:
                out.append((oid_val, snmp.SNMPValue(ber.TAG_END_OF_MIB_VIEW, None)))
            else:
                next_oid, value = result
                out.append((next_oid, value))

        repeating_oids = [vb[0] for vb in msg.varbinds[nr:]]
        for _ in range(max_repetitions):
            if not repeating_oids:
                break
            all_done = True
            for i, oid_val in enumerate(repeating_oids):
                result = self.cache.get_next(oid_val)
                if result is None:
                    out.append((oid_val, snmp.SNMPValue(ber.TAG_END_OF_MIB_VIEW, None)))
                else:
                    next_oid, value = result
                    out.append((next_oid, value))
                    repeating_oids[i] = next_oid
                    all_done = False
            if all_done:
                break

        return self._response(msg, snmp.ERR_NO_ERROR, 0, out)

    # --- response helpers ---

    def _response(self, msg, error_status, error_index, varbinds):
        return snmp.encode_message(
            msg.version, self.community, snmp.PDU_RESPONSE,
            msg.request_id, error_status, error_index, varbinds,
        )

    def _error_response(self, msg, error_status, error_index):
        echoed = [(oid_val, snmp.SNMPValue(ber.TAG_NULL, None))
                  for oid_val, _ in msg.varbinds]
        return self._response(msg, error_status, error_index, echoed)
