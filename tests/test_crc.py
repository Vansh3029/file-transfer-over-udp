import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from protocol import DATA, HEADER_SIZE, make_packet, parse_packet


class CRCTests(unittest.TestCase):
    def test_corrupted_payload_marks_crc_invalid(self):
        raw = bytearray(make_packet(3, DATA, b"abcdef"))
        raw[HEADER_SIZE + 2] ^= 0xFF
        packet = parse_packet(bytes(raw))
        self.assertFalse(packet.valid_crc)

    def test_corrupted_header_seq_marks_crc_invalid(self):
        raw = bytearray(make_packet(10, DATA, b"abcdef"))
        raw[1] ^= 0xFF  # Corrupt sequence number byte in header
        packet = parse_packet(bytes(raw))
        self.assertFalse(packet.valid_crc)

    def test_corrupted_header_type_marks_crc_invalid(self):
        raw = bytearray(make_packet(5, DATA, b"abcdef"))
        raw[4] = 4  # Change type from DATA to ACK
        packet = parse_packet(bytes(raw))
        self.assertFalse(packet.valid_crc)


if __name__ == "__main__":
    unittest.main()
