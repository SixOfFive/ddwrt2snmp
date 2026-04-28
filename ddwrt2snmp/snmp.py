"""SNMP v1/v2c message + PDU encode/decode on top of BER."""

from . import ber

# Versions on the wire
VERSION_V1  = 0
VERSION_V2C = 1

# PDU types (Context-specific, constructed)
PDU_GET      = 0xA0
PDU_GETNEXT  = 0xA1
PDU_RESPONSE = 0xA2
PDU_SET      = 0xA3
PDU_TRAP_V1  = 0xA4
PDU_GETBULK  = 0xA5
PDU_INFORM   = 0xA6
PDU_TRAP_V2  = 0xA7
PDU_REPORT   = 0xA8

# Error statuses
ERR_NO_ERROR             = 0
ERR_TOO_BIG              = 1
ERR_NO_SUCH_NAME         = 2  # v1 only
ERR_BAD_VALUE            = 3
ERR_READ_ONLY            = 4
ERR_GEN_ERR              = 5
ERR_NO_ACCESS            = 6
ERR_WRONG_TYPE           = 7
ERR_WRONG_LENGTH         = 8
ERR_WRONG_ENCODING       = 9
ERR_WRONG_VALUE          = 10
ERR_NO_CREATION          = 11
ERR_INCONSISTENT_VALUE   = 12
ERR_RESOURCE_UNAVAILABLE = 13
ERR_COMMIT_FAILED        = 14
ERR_UNDO_FAILED          = 15
ERR_AUTHORIZATION_ERROR  = 16
ERR_NOT_WRITABLE         = 17
ERR_INCONSISTENT_NAME    = 18


class SNMPError(Exception):
    pass


class SNMPValue:
    """A typed SNMP varbind value: (BER tag, native-Python value)."""

    __slots__ = ("tag", "value")

    def __init__(self, tag, value):
        self.tag = tag
        self.value = value

    def __repr__(self):
        return f"SNMPValue(tag=0x{self.tag:02x}, value={self.value!r})"


# --- typed-value constructors (use these from MIB definitions) ---

def integer(n):
    return SNMPValue(ber.TAG_INTEGER, int(n))

def octet_string(s):
    if isinstance(s, str):
        s = s.encode("utf-8")
    return SNMPValue(ber.TAG_OCTET_STRING, bytes(s))

def null():
    return SNMPValue(ber.TAG_NULL, None)

def oid(o):
    return SNMPValue(ber.TAG_OID, tuple(o))

def ip_address(addr):
    if isinstance(addr, str):
        addr = bytes(int(p) for p in addr.split("."))
    if len(addr) != 4:
        raise SNMPError(f"IpAddress must be 4 bytes, got {len(addr)}")
    return SNMPValue(ber.TAG_IPADDRESS, bytes(addr))

def counter32(n):
    return SNMPValue(ber.TAG_COUNTER32, int(n) & 0xFFFFFFFF)

def gauge32(n):
    return SNMPValue(ber.TAG_GAUGE32, int(n) & 0xFFFFFFFF)

def timeticks(n):
    return SNMPValue(ber.TAG_TIMETICKS, int(n) & 0xFFFFFFFF)

def counter64(n):
    return SNMPValue(ber.TAG_COUNTER64, int(n) & 0xFFFFFFFFFFFFFFFF)


# --- value encode/decode ---

def encode_value(v):
    t = v.tag
    if t == ber.TAG_NULL:
        content = b""
    elif t == ber.TAG_INTEGER:
        content = ber.encode_integer_value(v.value)
    elif t == ber.TAG_OCTET_STRING:
        content = v.value
    elif t == ber.TAG_OID:
        content = ber.encode_oid_value(v.value)
    elif t in (ber.TAG_COUNTER32, ber.TAG_GAUGE32, ber.TAG_TIMETICKS):
        content = ber.encode_unsigned32_value(v.value)
    elif t == ber.TAG_COUNTER64:
        content = ber.encode_unsigned64_value(v.value)
    elif t == ber.TAG_IPADDRESS:
        content = v.value
    elif t == ber.TAG_OPAQUE:
        content = v.value
    elif t in (ber.TAG_NO_SUCH_OBJECT, ber.TAG_NO_SUCH_INSTANCE, ber.TAG_END_OF_MIB_VIEW):
        content = b""
    else:
        raise SNMPError(f"unsupported value tag: 0x{t:02x}")
    return ber.encode_tlv(t, content)


def decode_value(tag, content):
    if tag == ber.TAG_NULL:
        return SNMPValue(tag, None)
    if tag == ber.TAG_INTEGER:
        return SNMPValue(tag, ber.decode_integer_value(content))
    if tag == ber.TAG_OCTET_STRING:
        return SNMPValue(tag, bytes(content))
    if tag == ber.TAG_OID:
        return SNMPValue(tag, ber.decode_oid_value(content))
    if tag in (ber.TAG_COUNTER32, ber.TAG_GAUGE32, ber.TAG_TIMETICKS, ber.TAG_COUNTER64):
        return SNMPValue(tag, ber.decode_unsigned_value(content))
    if tag == ber.TAG_IPADDRESS:
        return SNMPValue(tag, bytes(content))
    if tag in (ber.TAG_NO_SUCH_OBJECT, ber.TAG_NO_SUCH_INSTANCE, ber.TAG_END_OF_MIB_VIEW):
        return SNMPValue(tag, None)
    return SNMPValue(tag, bytes(content))


# --- message parse / build ---

class Message:
    __slots__ = ("version", "community", "pdu_type", "request_id",
                 "error_status", "error_index", "varbinds")

    def __repr__(self):
        return (f"Message(v={self.version}, community={self.community!r}, "
                f"pdu=0x{self.pdu_type:02x}, req_id={self.request_id}, "
                f"err={self.error_status}/{self.error_index}, "
                f"vbs={self.varbinds!r})")


def decode_message(data):
    tag, content, _ = ber.parse_tlv(data, 0)
    if tag != ber.TAG_SEQUENCE:
        raise SNMPError("expected SEQUENCE at top of SNMP message")

    pos = 0
    t, c, pos = ber.parse_tlv(content, pos)
    if t != ber.TAG_INTEGER:
        raise SNMPError("expected INTEGER for version")
    version = ber.decode_integer_value(c)

    t, c, pos = ber.parse_tlv(content, pos)
    if t != ber.TAG_OCTET_STRING:
        raise SNMPError("expected OCTET STRING for community")
    community = bytes(c)

    pdu_tag, pdu_body, _ = ber.parse_tlv(content, pos)

    pp = 0
    t, c, pp = ber.parse_tlv(pdu_body, pp)
    request_id = ber.decode_integer_value(c)

    t, c, pp = ber.parse_tlv(pdu_body, pp)
    error_status = ber.decode_integer_value(c)

    t, c, pp = ber.parse_tlv(pdu_body, pp)
    error_index = ber.decode_integer_value(c)

    t, c, pp = ber.parse_tlv(pdu_body, pp)
    if t != ber.TAG_SEQUENCE:
        raise SNMPError("expected SEQUENCE OF VarBind")

    varbinds = []
    vp = 0
    while vp < len(c):
        vbtag, vbcontent, vp = ber.parse_tlv(c, vp)
        if vbtag != ber.TAG_SEQUENCE:
            raise SNMPError("expected VarBind SEQUENCE")
        ip = 0
        otag, ocontent, ip = ber.parse_tlv(vbcontent, ip)
        if otag != ber.TAG_OID:
            raise SNMPError("expected OID in VarBind")
        oid_val = ber.decode_oid_value(ocontent)
        vtag, vcontent, _ = ber.parse_tlv(vbcontent, ip)
        value = decode_value(vtag, vcontent)
        varbinds.append((oid_val, value))

    msg = Message()
    msg.version = version
    msg.community = community
    msg.pdu_type = pdu_tag
    msg.request_id = request_id
    msg.error_status = error_status
    msg.error_index = error_index
    msg.varbinds = varbinds
    return msg


def encode_message(version, community, pdu_type, request_id,
                   error_status, error_index, varbinds):
    if isinstance(community, str):
        community = community.encode("utf-8")

    vb_seq = b""
    for oid_val, value in varbinds:
        oid_tlv = ber.encode_tlv(ber.TAG_OID, ber.encode_oid_value(oid_val))
        val_tlv = encode_value(value)
        vb_seq += ber.encode_tlv(ber.TAG_SEQUENCE, oid_tlv + val_tlv)
    vbs = ber.encode_tlv(ber.TAG_SEQUENCE, vb_seq)

    pdu_body = (
        ber.encode_tlv(ber.TAG_INTEGER, ber.encode_integer_value(request_id)) +
        ber.encode_tlv(ber.TAG_INTEGER, ber.encode_integer_value(error_status)) +
        ber.encode_tlv(ber.TAG_INTEGER, ber.encode_integer_value(error_index)) +
        vbs
    )
    pdu = ber.encode_tlv(pdu_type, pdu_body)

    msg_body = (
        ber.encode_tlv(ber.TAG_INTEGER, ber.encode_integer_value(version)) +
        ber.encode_tlv(ber.TAG_OCTET_STRING, community) +
        pdu
    )
    return ber.encode_tlv(ber.TAG_SEQUENCE, msg_body)
