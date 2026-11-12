"""Minimal ASN.1 BER codec for SNMPv1 messages (RFC 1157), no third-party dependencies.

Supported types: INTEGER, OCTET STRING, NULL, OBJECT IDENTIFIER, SEQUENCE and the SNMPv1
PDUs GetRequest (0xA0), GetNextRequest (0xA1), GetResponse (0xA2) and SetRequest (0xA3).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Union

from ..core.exceptions import SNMPError

INTEGER, OCTET_STRING, NULL, OID, SEQUENCE = 0x02, 0x04, 0x05, 0x06, 0x30
GET, GET_NEXT, RESPONSE, SET = 0xA0, 0xA1, 0xA2, 0xA3
NO_ERROR, TOO_BIG, NO_SUCH_NAME, BAD_VALUE, READ_ONLY, GEN_ERR = 0, 1, 2, 3, 4, 5

Value = Union[int, bytes, None, tuple[int, ...]]


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(out)]) + out


def tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _len(len(payload)) + payload


def enc_int(v: int) -> bytes:
    n = max(1, (v.bit_length() + 8) // 8)
    return tlv(INTEGER, v.to_bytes(n, "big", signed=True))


def enc_oid(oid: tuple[int, ...]) -> bytes:
    if len(oid) < 2 or oid[0] > 2 or (oid[0] < 2 and oid[1] > 39):
        raise SNMPError("invalid OID", context={"oid": oid})
    out = bytearray([40 * oid[0] + oid[1]])
    for arc in oid[2:]:
        if arc < 0:
            raise SNMPError("negative OID arc")
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        out.extend(reversed(chunk))
    return tlv(OID, bytes(out))


def enc_value(v: Value) -> bytes:
    if v is None:
        return tlv(NULL, b"")
    if isinstance(v, bool):
        return enc_int(int(v))
    if isinstance(v, int):
        return enc_int(v)
    if isinstance(v, bytes):
        return tlv(OCTET_STRING, v)
    if isinstance(v, tuple):
        return enc_oid(v)
    raise SNMPError("unsupported value type", context={"type": type(v).__name__})


def _read_tlv(buf: bytes, pos: int) -> tuple[int, bytes, int]:
    if pos + 2 > len(buf):
        raise SNMPError("truncated TLV")
    tag = buf[pos]
    ln = buf[pos + 1]
    pos += 2
    if ln & 0x80:
        k = ln & 0x7F
        if k == 0 or k > 4 or pos + k > len(buf):
            raise SNMPError("bad length")
        ln = int.from_bytes(buf[pos : pos + k], "big")
        pos += k
    if pos + ln > len(buf):
        raise SNMPError("value exceeds buffer")
    return tag, buf[pos : pos + ln], pos + ln


def dec_oid(b: bytes) -> tuple[int, ...]:
    if not b:
        raise SNMPError("empty OID")
    first = b[0]
    arcs = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    val = 0
    for byte in b[1:]:
        val = (val << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(val)
            val = 0
    return tuple(arcs)


def dec_value(tag: int, b: bytes) -> Value:
    if tag == INTEGER:
        return int.from_bytes(b, "big", signed=True) if b else 0
    if tag == OCTET_STRING:
        return bytes(b)
    if tag == NULL:
        return None
    if tag == OID:
        return dec_oid(b)
    raise SNMPError("unsupported value tag", context={"tag": hex(tag)})


@dataclass
class Message:
    pdu_type: int
    request_id: int
    varbinds: list[tuple[tuple[int, ...], Value]] = field(default_factory=list)
    community: bytes = b"public"
    error_status: int = NO_ERROR
    error_index: int = 0
    version: int = 0

    def encode(self) -> bytes:
        vbs = b"".join(tlv(SEQUENCE, enc_oid(o) + enc_value(v)) for o, v in self.varbinds)
        pdu = tlv(self.pdu_type, enc_int(self.request_id) + enc_int(self.error_status) + enc_int(self.error_index)
                  + tlv(SEQUENCE, vbs))
        return tlv(SEQUENCE, enc_int(self.version) + tlv(OCTET_STRING, self.community) + pdu)

    @classmethod
    def decode(cls, data: bytes) -> "Message":
        tag, body, end = _read_tlv(data, 0)
        if tag != SEQUENCE or end != len(data):
            raise SNMPError("message is not a single SEQUENCE")
        t, ver, p = _read_tlv(body, 0)
        t2, comm, p = _read_tlv(body, p)
        pdu_tag, pdu, p = _read_tlv(body, p)
        if t != INTEGER or t2 != OCTET_STRING or pdu_tag not in (GET, GET_NEXT, RESPONSE, SET):
            raise SNMPError("malformed SNMP header")
        _, rid, q = _read_tlv(pdu, 0)
        _, es, q = _read_tlv(pdu, q)
        _, ei, q = _read_tlv(pdu, q)
        vt, vlist, _ = _read_tlv(pdu, q)
        if vt != SEQUENCE:
            raise SNMPError("varbind list is not a SEQUENCE")
        vbs: list[tuple[tuple[int, ...], Value]] = []
        pos = 0
        while pos < len(vlist):
            st, vb, pos = _read_tlv(vlist, pos)
            if st != SEQUENCE:
                raise SNMPError("varbind is not a SEQUENCE")
            ot, ob, r = _read_tlv(vb, 0)
            vtag, vv, _ = _read_tlv(vb, r)
            if ot != OID:
                raise SNMPError("varbind name is not an OID")
            vbs.append((dec_oid(ob), dec_value(vtag, vv)))
        return cls(pdu_tag, int(dec_value(INTEGER, rid)), vbs, bytes(comm), int(dec_value(INTEGER, es)),  # type: ignore[arg-type]
                   int(dec_value(INTEGER, ei)), int(dec_value(INTEGER, ver)))  # type: ignore[arg-type]
