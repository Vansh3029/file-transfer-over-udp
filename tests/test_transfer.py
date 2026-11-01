import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from integrity import sha256_file
from state import STATE
from udp_receiver import UDPReceiver
from udp_sender import ReliableUDPSender


class TransferTests(unittest.TestCase):
    def setUp(self):
        STATE.reset()
        self.stop_event = threading.Event()
        self.receiver = UDPReceiver(STATE, host="127.0.0.1", port=9000, stop_event=self.stop_event)
        self.receiver.start()
        self.receiver.ready_event.wait(timeout=2.0)

    def tearDown(self):
        self.stop_event.set()
        self.receiver.join(timeout=2.0)

    def test_transfer_with_loss_verifies_hash(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.bin"
            path.write_bytes(os.urandom(24 * 1024))
            sender_hash = sha256_file(path)
            ReliableUDPSender(STATE, path, window_size=8, timeout_ms=120, packet_loss=10).run()
            snapshot = STATE.snapshot()["state"]
            self.assertEqual(snapshot["integrity_status"], "VERIFIED")
            self.assertEqual(snapshot["sender_hash"], sender_hash)
            self.assertEqual(snapshot["sender_hash"], snapshot["receiver_hash"])
            self.assertGreaterEqual(snapshot["packets_lost"] + snapshot["retransmissions"], 0)

    def test_transfer_zero_loss(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "zero_loss.bin"
            path.write_bytes(os.urandom(16 * 1024))
            sender_hash = sha256_file(path)
            ReliableUDPSender(STATE, path, window_size=8, timeout_ms=100, packet_loss=0).run()
            snapshot = STATE.snapshot()["state"]
            self.assertEqual(snapshot["integrity_status"], "VERIFIED")
            self.assertEqual(snapshot["sender_hash"], sender_hash)
            self.assertEqual(snapshot["sender_hash"], snapshot["receiver_hash"])
            self.assertEqual(snapshot["packets_lost"], 0)

    def test_transfer_stop_and_wait(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "stop_wait.bin"
            path.write_bytes(os.urandom(8 * 1024))
            sender_hash = sha256_file(path)
            ReliableUDPSender(STATE, path, window_size=1, timeout_ms=80, packet_loss=10).run()
            snapshot = STATE.snapshot()["state"]
            self.assertEqual(snapshot["integrity_status"], "VERIFIED")
            self.assertEqual(snapshot["sender_hash"], sender_hash)
            self.assertEqual(snapshot["sender_hash"], snapshot["receiver_hash"])


if __name__ == "__main__":
    unittest.main()
