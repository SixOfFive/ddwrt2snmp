"""ASN.1 BER encode/decode — only the subset SNMPv1/v2c needs."""

# Universal class
TAG_INTEGER       = 0x02
TAG_OCTET_STRING  = 0x04
TAG_NULL          = 0x05
TAG_OID           = 0x06
TAG_SEQUENCE      = 0x30  # constructed, universal 16

# SNMP Application class (primitive)
TAG_IPADDRESS  = 0x40
TAG_COUNTER32  = 0x41
TAG_GAUGE32    = 0x42  # also Unsigned32
TAG_TIMETICKS  = 0x43
TAG_OPAQUE     = 0x44
TAG_COUNTER64  = 0x46

# v2c VarBind exception markers (Context-specific, primitive, length 0)
TAG_NO_SUCH_OBJECT   = 0x80
TAG_NO_SUCH_INSTANCE = 0x81
TAG_END_OF_MIB_VIEW  = 0x82


class BERError(ValueError):
    pass


# --- length ---

def encode_length(n):
    if n < 0:
        raise BERError("length cannot be negative")
    if n < 0x80:
        return bytes([n])
    raw = []
    while n > 0:
        raw.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(raw)]) + bytes(raw)


def decode_length(buf, pos):
    first = buf[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    nbytes = first & 0x7F
    if nbytes == 0:
        raise BERError("indefinite-length encoding not supported")
    if pos + nbytes > len(buf):
        raise BERError("truncated length")
    length = 0
    for _ in range(nbytes):
        length = (length << 8) | buf[pos]
        pos += 1
    return length, pos


# --- TLV ---

def encode_tlv(tag, content):
    return bytes([tag]) + encode_length(len(content)) + content


def parse_tlv(buf, pos=0):
    """Return (tag, content_bytes, next_pos)."""
    if pos >= len(buf):
        raise BERError("unexpected end of buffer")
    tag = buf[pos]
    pos += 1
    length, pos = decode_length(buf, pos)
    end = pos + length
    if end > len(buf):
        raise BERError("TLV content runs past end of buffer")
    return tag, buf[pos:end], end


# --- INTEGER (signed, two's complement, minimum bytes) ---

def encode_integer_value(n):
    size = 1
    while True:
        try:
            return n.to_bytes(size, "big", signed=True)
        except OverflowError:
            size += 1


def decode_integer_value(buf):
    if not buf:
        raise BERError("empty INTEGER")
    return int.from_bytes(buf, "big", signed=True)


# --- Counter32 / Gauge32 / TimeTicks (encoded per BER INTEGER rules but unsigned) ---

def encode_unsigned32_value(n):
    if n < 0 or n > 0xFFFFFFFF:
        raise BERError(f"unsigned32 out of range: {n}")
    return _encode_unsigned(n)


def encode_unsigned64_value(n):
    if n < 0 or n > 0xFFFFFFFFFFFFFFFF:
        raise BERError(f"unsigned64 out of range: {n}")
    return _encode_unsigned(n)


def _encode_unsigned(n):
    if n == 0:
        return b"\x00"
    nbytes = (n.bit_length() + 7) // 8
    out = n.to_bytes(nbytes, "big")
    # Per BER INTEGER rules, prepend 0x00 if high bit is set (so the value
    # would otherwise be parsed as negative).
    if out[0] & 0x80:
        out = b"\x00" + out
    return out


def decode_unsigned_value(buf):
    if not buf:
        return 0
    return int.from_bytes(buf, "big", signed=False)


# --- OBJECT IDENTIFIER ---

def encode_oid_value(oid):
    """oid is a tuple/list of non-negative ints; must have at least 2 components."""
    if len(oid) < 2:
        raise BERError("OID must have at least 2 components")
    a, b = oid[0], oid[1]
    if a < 0 or a > 2:
        raise BERError(f"first OID arc must be 0..2, got {a}")
    if a < 2 and b >= 40:
        raise BERError(f"second OID arc must be < 40 when first arc is {a}")
    out = bytearray()
    arcs = [40 * a + b] + list(oid[2:])
    for arc in arcs:
        if arc < 0:
            raise BERError("negative OID arc")
        if arc < 0x80:
            out.append(arc)
            continue
        chunks = []
        while arc > 0:
            chunks.insert(0, arc & 0x7F)
            arc >>= 7
        for i in range(len(chunks) - 1):
            chunks[i] |= 0x80
        out.extend(chunks)
    return bytes(out)


def decode_oid_value(buf):
    if not buf:
        return ()
    arcs = []
    i = 0
    while i < len(buf):
        arc = 0
        while True:
            if i >= len(buf):
                raise BERError("truncated OID arc")
            byte = buf[i]
            i += 1
            arc = (arc << 7) | (byte & 0x7F)
            if not (byte & 0x80):
                break
        arcs.append(arc)
    first = arcs[0]
    if first < 40:
        decoded = [0, first]
    elif first < 80:
        decoded = [1, first - 40]
    else:
        decoded = [2, first - 80]
    decoded.extend(arcs[1:])
    return tuple(decoded)


def oid_str(oid):
    return ".".join(str(a) for a in oid)


def oid_from_str(s):
    s = s.strip().lstrip(".")
    return tuple(int(p) for p in s.split("."))
