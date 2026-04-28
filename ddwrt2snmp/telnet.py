"""Raw-socket telnet client.

Refuses every option negotiation (stays in NVT mode), auto-detects login and
password prompts case-insensitively, then brackets each command with a unique
sentinel so output parsing doesn't depend on the router's prompt or banner.
"""

import logging
import re
import secrets
import socket
import time

log = logging.getLogger(__name__)

# Telnet command bytes
IAC  = 0xFF
DONT = 0xFE
DO   = 0xFD
WONT = 0xFC
WILL = 0xFB
SB   = 0xFA
SE   = 0xF0


class TelnetError(Exception):
    pass


class TelnetTimeout(TelnetError):
    pass


class TelnetClient:
    LOGIN_PROMPTS    = (b"login:", b"username:", b"user:")
    PASSWORD_PROMPTS = (b"password:", b"passcode:", b"passwd:")
    LOGIN_FAIL_HINTS = (b"incorrect", b"login failed", b"authentication failed",
                        b"access denied")

    def __init__(self, host, port=23, connect_timeout=10.0):
        self.host = host
        self.port = port
        self.connect_timeout = connect_timeout
        self._sock = None
        self._buf = bytearray()
        self._cmd_counter = 0
        # IAC parsing state machine
        self._iac_state = 0
        self._iac_cmd = 0

    # --- lifecycle ---

    def connect(self):
        self._sock = socket.create_connection(
            (self.host, self.port), timeout=self.connect_timeout)
        log.debug("telnet: connected to %s:%d", self.host, self.port)

    def close(self):
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        self._buf.clear()
        self._iac_state = 0

    # --- low-level I/O ---

    def _send(self, data):
        # IAC (0xFF) bytes in user data must be doubled.
        if 0xFF in data:
            data = data.replace(b"\xff", b"\xff\xff")
        self._sock.sendall(data)

    def _read_some(self, deadline):
        """Read whatever bytes are available before deadline, processing IAC.
        Returns True if any user data was added to the buffer, False if the
        deadline was reached without progress."""
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            slice_timeout = min(remaining, 0.5)
            self._sock.settimeout(slice_timeout)
            try:
                chunk = self._sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                raise TelnetError("connection closed by peer")
            grew = self._process_chunk(chunk)
            if grew:
                return True
            # All bytes were swallowed by IAC handling — keep reading.

    def _process_chunk(self, chunk):
        """Feed bytes through the IAC state machine; user data goes to _buf.
        Returns True if any user data was appended."""
        added = False
        for b in chunk:
            if self._iac_state == 0:
                if b == IAC:
                    self._iac_state = 1
                else:
                    self._buf.append(b)
                    added = True
            elif self._iac_state == 1:
                if b == IAC:
                    self._buf.append(0xFF)  # escaped 0xFF
                    self._iac_state = 0
                    added = True
                elif b in (DO, DONT, WILL, WONT):
                    self._iac_cmd = b
                    self._iac_state = 2
                elif b == SB:
                    self._iac_state = 3
                else:
                    # Other 2-byte commands (NOP, AYT, BRK, ...) — drop.
                    self._iac_state = 0
            elif self._iac_state == 2:
                self._respond_negotiation(self._iac_cmd, b)
                self._iac_state = 0
            elif self._iac_state == 3:  # inside SB
                if b == IAC:
                    self._iac_state = 4
            elif self._iac_state == 4:  # IAC seen inside SB
                if b == SE:
                    self._iac_state = 0
                elif b == IAC:
                    self._iac_state = 3  # escaped IAC inside SB
                else:
                    self._iac_state = 0
        return added

    def _respond_negotiation(self, cmd, opt):
        # Refuse every option to stay in NVT mode.
        if cmd == DO:
            reply = bytes([IAC, WONT, opt])
        elif cmd == WILL:
            reply = bytes([IAC, DONT, opt])
        elif cmd == DONT:
            reply = bytes([IAC, WONT, opt])
        elif cmd == WONT:
            reply = bytes([IAC, DONT, opt])
        else:
            return
        try:
            self._sock.sendall(reply)
        except OSError as e:
            log.debug("telnet: failed to send IAC reply: %s", e)

    def _read_until(self, pattern, timeout):
        """Read until `pattern` (bytes literal or compiled regex) is found.
        Consumes the matched bytes from the buffer; returns them. For regex,
        also returns a Match object that references the returned bytes."""
        deadline = time.monotonic() + timeout
        is_regex = not isinstance(pattern, (bytes, bytearray))
        while True:
            if is_regex:
                # Search a stable bytes copy so the Match object stays valid
                # after we mutate the buffer.
                snapshot = bytes(self._buf)
                m = pattern.search(snapshot)
                if m:
                    end = m.end()
                    out = snapshot[:end]
                    del self._buf[:end]
                    return out, m
            else:
                idx = self._buf.find(pattern)
                if idx >= 0:
                    end = idx + len(pattern)
                    out = bytes(self._buf[:end])
                    del self._buf[:end]
                    return out
            if not self._read_some(deadline):
                tail = bytes(self._buf[-200:])
                raise TelnetTimeout(
                    f"timeout waiting for {pattern!r}; tail={tail!r}")

    def _read_until_any(self, patterns, timeout):
        """Wait for any of the byte patterns (case-insensitive). Returns
        (matched_index, raw_bytes_through_match)."""
        rx = re.compile(
            b"(" + b"|".join(re.escape(p) for p in patterns) + b")",
            re.IGNORECASE)
        out, m = self._read_until(rx, timeout)
        matched = m.group(1).lower()
        for i, p in enumerate(patterns):
            if matched == p.lower():
                return i, out
        return -1, out

    def _drain(self, idle_timeout=0.5):
        """Consume bytes until the connection is idle for idle_timeout."""
        deadline = time.monotonic() + idle_timeout
        try:
            while time.monotonic() < deadline:
                self._read_some(deadline)
        except TelnetError:
            pass

    # --- high-level ---

    def login(self, user, password, timeout=15.0):
        log.debug("telnet: waiting for login prompt")
        try:
            self._read_until_any(self.LOGIN_PROMPTS, timeout)
        except TelnetTimeout as e:
            raise TelnetError(f"never saw login prompt ({e})")
        self._send((user + "\r\n").encode())

        try:
            self._read_until_any(self.PASSWORD_PROMPTS, timeout)
        except TelnetTimeout as e:
            raise TelnetError(f"never saw password prompt ({e})")
        self._send((password + "\r\n").encode())

        # Give the server a moment to print its banner / shell prompt.
        self._drain(idle_timeout=1.0)

        # Sniff for failed-auth indicators.
        recent = bytes(self._buf).lower()
        for hint in self.LOGIN_FAIL_HINTS:
            if hint in recent:
                raise TelnetError(
                    f"login failed (hint={hint!r}); buffer tail={recent[-200:]!r}")
        for p in self.LOGIN_PROMPTS:
            if p in recent:
                raise TelnetError("login prompt reappeared (auth failed)")

        log.debug("telnet: authenticated; preparing shell")
        self._setup_shell()
        log.info("telnet: shell ready on %s:%d", self.host, self.port)

    PROMPT = b"__PS_DDWRT__> "

    def _setup_shell(self):
        # Try to disable echo (best-effort) and set a known prompt. The READY
        # marker uses '' so the input echo (if any) won't match our wait-
        # pattern: input has R'E'ADY but the printed output has READY.
        self._buf.clear()
        self._send(
            b"stty -echo 2>/dev/null; "
            b"PS1='__PS_DDWRT__> '; "
            b"echo R'E'ADY_DDWRT_SETUP\r\n"
        )
        self._read_until(re.compile(rb"READY_DDWRT_SETUP\r?\n"), timeout=10.0)
        # Consume the next prompt so the buffer is empty before any run().
        self._read_until(self.PROMPT, timeout=5.0)

    def run(self, cmd, timeout=10.0):
        """Run a single shell command. Returns (stdout_text, exit_code)."""
        self._cmd_counter += 1
        sentinel = f"__SX_{self._cmd_counter:06x}_{secrets.token_hex(2)}__"
        # Combine stderr with stdout, then mark the end with sentinel + exit code.
        # Sentinel form is `<sent>=<digits>=` in OUTPUT, but the input line
        # contains `<sent>=$?=` — \d+ in the regex distinguishes them.
        # Require the next prompt to follow so the buffer is clean for the
        # next call (and any pre-existing prompt at the head of the buffer
        # gets included in `body` and stripped by line filtering).
        payload = f"{cmd} 2>&1; echo {sentinel}=$?=\r\n".encode()
        self._send(payload)

        pattern = re.compile(
            re.escape(sentinel.encode()) + rb"=(\d+)=\r?\n"
            + re.escape(self.PROMPT)
        )
        raw, m = self._read_until(pattern, timeout)
        exit_code = int(m.group(1))

        body = raw[:m.start()].decode("utf-8", errors="replace")

        # A leading prompt (from the previous command's tail) may sit at the
        # very start of `body`. Strip exactly one leading prompt if present.
        prompt_str = self.PROMPT.decode()
        if body.startswith(prompt_str):
            body = body[len(prompt_str):]

        lines = body.splitlines()
        # Strip lines that contain the input echo of our sentinel (the line
        # we typed, with `$?` instead of digits).
        sentinel_marker = f"echo {sentinel}"
        cleaned = [ln for ln in lines if sentinel_marker not in ln]
        while cleaned and cleaned[0].strip() == "":
            cleaned.pop(0)
        while cleaned and cleaned[-1].strip() == "":
            cleaned.pop()

        return "\n".join(cleaned), exit_code
