import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from integrity import sha256_file
from protocol import DATA, HEADER_SIZE, make_packet, parse_packet
from state import STATE
from udp_receiver import UDPReceiver, sanitize_filename
from udp_sender import ReliableUDPSender


class EdgeCaseTests(unittest.TestCase):
    def setUp(self):
        STATE.reset()
        self.stop_event = threading.Event()
        self.receiver = UDPReceiver(STATE, host="127.0.0.1", port=9000, stop_event=self.stop_event)
        self.receiver.start()
        self.receiver.ready_event.wait(timeout=2.0)

    def tearDown(self):
        self.stop_event.set()
        self.receiver.join(timeout=2.0)

    def test_empty_file_transfer(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "empty.bin"
            path.write_bytes(b"")
            sender_hash = sha256_file(path)
            ReliableUDPSender(STATE, path, window_size=4, timeout_ms=80, packet_loss=0).run()
            snapshot = STATE.snapshot()["state"]
            self.assertEqual(snapshot["integrity_status"], "VERIFIED")
            self.assertEqual(snapshot["sender_hash"], sender_hash)
            self.assertEqual(snapshot["receiver_hash"], sender_hash)
            self.assertEqual(snapshot["file_size"], 0)

    def test_single_byte_file_transfer(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "single_byte.bin"
            path.write_bytes(b"Z")
            sender_hash = sha256_file(path)
            ReliableUDPSender(STATE, path, window_size=4, timeout_ms=80, packet_loss=10).run()
            snapshot = STATE.snapshot()["state"]
            self.assertEqual(snapshot["integrity_status"], "VERIFIED")
            self.assertEqual(snapshot["sender_hash"], sender_hash)
            self.assertEqual(snapshot["receiver_hash"], sender_hash)
            self.assertEqual(snapshot["file_size"], 1)

    def test_exact_chunk_boundary_transfers(self):
        for size in (1024, 2048, 1025):
            with tempfile.TemporaryDirectory() as temp_dir:
                path = Path(temp_dir) / f"boundary_{size}.bin"
                path.write_bytes(os.urandom(size))
                sender_hash = sha256_file(path)
                ReliableUDPSender(STATE, path, window_size=8, timeout_ms=100, packet_loss=10).run()
                snapshot = STATE.snapshot()["state"]
                self.assertEqual(snapshot["integrity_status"], "VERIFIED", f"Failed for size {size}")
                self.assertEqual(snapshot["sender_hash"], sender_hash)
                self.assertEqual(snapshot["receiver_hash"], sender_hash)

    def test_filename_sanitization_security(self):
        # Path traversal tests
        self.assertEqual(sanitize_filename("../../etc/passwd"), "passwd")
        self.assertEqual(sanitize_filename(".."), "received_file.bin")
        self.assertEqual(sanitize_filename("..."), "received_file.bin")
        self.assertEqual(sanitize_filename(""), "received_file.bin")
        self.assertEqual(sanitize_filename("   "), "received_file.bin")

        # Windows reserved device names
        self.assertTrue(sanitize_filename("CON.txt").startswith("safe_"))
        self.assertTrue(sanitize_filename("nul").startswith("safe_"))
        self.assertTrue(sanitize_filename("aux.bin").startswith("safe_"))

        # Valid names preserved
        self.assertEqual(sanitize_filename("my-document_v1.0.pdf"), "my-document_v1.0.pdf")


if __name__ == "__main__":
    unittest.main()

