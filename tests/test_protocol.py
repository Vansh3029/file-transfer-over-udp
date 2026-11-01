import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from protocol import DATA, HEADER, PAYLOAD_SIZE, ProtocolError, make_packet, parse_packet


class ProtocolTests(unittest.TestCase):
    def test_packet_header_format_and_crc(self):
        payload = b"hello"
        raw = make_packet(7, DATA, payload)
        packet = parse_packet(raw)
        self.assertEqual(HEADER.format, "!IBHI")
        self.assertEqual(packet.seq, 7)
        self.assertEqual(packet.type, DATA)
        self.assertEqual(packet.length, len(payload))
        self.assertTrue(packet.valid_crc)
        self.assertEqual(packet.payload, payload)

    def test_rejects_bad_length(self):
        raw = make_packet(1, DATA, b"abc")[:-1]
        with self.assertRaises(ProtocolError):
            parse_packet(raw)

    def test_supports_1024_byte_payload(self):
        raw = make_packet(2, DATA, b"x" * PAYLOAD_SIZE)
        packet = parse_packet(raw)
        self.assertEqual(packet.length, PAYLOAD_SIZE)
        self.assertTrue(packet.valid_crc)


if __name__ == "__main__":
    unittest.main()
