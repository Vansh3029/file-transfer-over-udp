import json
import struct
import zlib
from dataclasses import dataclass


HEADER = struct.Struct("!IBHI")
HEADER_FIELDS = struct.Struct("!IBH")
HEADER_SIZE = HEADER.size
PAYLOAD_SIZE = 1024

START = 1
READY = 2
DATA = 3
ACK = 4
FIN = 5
FIN_ACK = 6

TYPE_NAMES = {
    START: "START",
    READY: "READY",
    DATA: "DATA",
    ACK: "ACK",
    FIN: "FIN",
    FIN_ACK: "FIN_ACK",
}


class ProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class Packet:
    seq: int
    type: int
    length: int
    crc32: int
    payload: bytes
    valid_crc: bool

    @property
    def type_name(self) -> str:
        return TYPE_NAMES.get(self.type, f"UNKNOWN({self.type})")


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def compute_packet_crc(seq: int, packet_type: int, payload: bytes) -> int:
    prefix = HEADER_FIELDS.pack(seq, packet_type, len(payload))
    return zlib.crc32(prefix + payload) & 0xFFFFFFFF


def make_packet(seq: int, packet_type: int, payload: bytes = b"") -> bytes:
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes")
    payload = bytes(payload)
    if len(payload) > 65535:
        raise ProtocolError("payload is too large for protocol length field")
    if seq < 0 or seq > 0xFFFFFFFF:
        raise ProtocolError("sequence number must fit in unsigned 32-bit")
    if packet_type not in TYPE_NAMES:
        raise ProtocolError("unknown packet type")
    checksum = compute_packet_crc(seq, packet_type, payload)
    header = HEADER.pack(seq, packet_type, len(payload), checksum)
    return header + payload


def parse_packet(raw: bytes) -> Packet:
    if len(raw) < HEADER_SIZE:
        raise ProtocolError("packet shorter than header")
    seq, packet_type, length, packet_crc = HEADER.unpack(raw[:HEADER_SIZE])
    payload = raw[HEADER_SIZE:]
    if len(payload) != length:
        raise ProtocolError("payload length does not match header length")
    if packet_type not in TYPE_NAMES:
        raise ProtocolError("unknown packet type")
    expected_crc = compute_packet_crc(seq, packet_type, payload)
    valid_crc = (packet_crc == expected_crc) or (packet_crc == crc32(payload))
    return Packet(
        seq=seq,
        type=packet_type,
        length=length,
        crc32=packet_crc,
        payload=payload,
        valid_crc=valid_crc,
    )


def encode_metadata(metadata: dict) -> bytes:
    return json.dumps(metadata, separators=(",", ":")).encode("utf-8")


def decode_metadata(payload: bytes) -> dict:
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("invalid metadata payload") from exc
