import hashlib
import ipaddress
import json
import os
import select
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app import AppHandler, validate_ipv4, validate_port
from config import PAYLOAD_SIZE, UDP_HOST
from http.server import ThreadingHTTPServer
from integrity import sha256_file
from protocol import ACK, DATA, FIN, FIN_ACK, READY, START, decode_metadata, encode_metadata, make_packet, parse_packet
from state import STATE
from udp_receiver import UDPReceiver
from udp_sender import ReliableUDPSender


class ReceiverConfigTests(unittest.TestCase):
    def setUp(self):
        STATE.reset()

    def test_ip_validation_logic(self):
        # Valid IPv4 addresses
        self.assertTrue(validate_ipv4("127.0.0.1"))
        self.assertTrue(validate_ipv4("192.168.1.1"))
        self.assertTrue(validate_ipv4("10.0.0.50"))
        self.assertTrue(validate_ipv4("172.16.0.1"))
        self.assertTrue(validate_ipv4("0.0.0.0"))

        # Invalid IP addresses
        self.assertFalse(validate_ipv4("999.999.999.999"))
        self.assertFalse(validate_ipv4("192.168.1"))
        self.assertFalse(validate_ipv4("192.168.1.1.1"))
        self.assertFalse(validate_ipv4("localhost"))
        self.assertFalse(validate_ipv4("example.com"))
        self.assertFalse(validate_ipv4(""))
        self.assertFalse(validate_ipv4(None))
        self.assertFalse(validate_ipv4("::1"))  # IPv6 not supported by IPv4-only validator

    def test_port_validation_logic(self):
        # Valid ports
        self.assertEqual(validate_port(1), 1)
        self.assertEqual(validate_port(9000), 9000)
        self.assertEqual(validate_port("9000"), 9000)
        self.assertEqual(validate_port(65535), 65535)

        # Invalid ports
        self.assertIsNone(validate_port(0))
        self.assertIsNone(validate_port(-1))
        self.assertIsNone(validate_port(65536))
        self.assertIsNone(validate_port("70000"))
        self.assertIsNone(validate_port("invalid"))
        self.assertIsNone(validate_port(None))

    def test_receiver_not_running(self):
        """Sender targets an inactive port (9876) where no receiver is running"""
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "test.bin"
            path.write_bytes(b"hello world")
            sender = ReliableUDPSender(STATE, path, window_size=4, timeout_ms=50, packet_loss=0, receiver_ip="127.0.0.1", receiver_port=9876)
            sender.run()
            snapshot = STATE.snapshot()["state"]
            self.assertEqual(snapshot["status"], "failed")
            self.assertEqual(snapshot["receiver_status"], "Connection Failed")
            self.assertIn("Handshake timed out", snapshot["message"])

    def test_wrong_udp_port(self):
        """Receiver listens on 9123; sender targets 9124"""
        stop_event = threading.Event()
        receiver = UDPReceiver(STATE, host="127.0.0.1", port=9123, stop_event=stop_event)
        receiver.start()
        self.assertTrue(receiver.ready_event.wait(timeout=2.0))

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                path = Path(temp_dir) / "wrong_port.bin"
                path.write_bytes(b"payload")
                sender = ReliableUDPSender(STATE, path, window_size=4, timeout_ms=50, packet_loss=0, receiver_ip="127.0.0.1", receiver_port=9124)
                sender.run()
                snapshot = STATE.snapshot()["state"]
                self.assertEqual(snapshot["status"], "failed")
                self.assertEqual(snapshot["receiver_status"], "Connection Failed")
        finally:
            stop_event.set()
            receiver.join(timeout=2.0)

    def test_unreachable_receiver(self):
        """Sender targets non-routable TEST-NET IP 192.0.2.1"""
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "unreachable.bin"
            path.write_bytes(b"data")
            sender = ReliableUDPSender(STATE, path, window_size=4, timeout_ms=50, packet_loss=0, receiver_ip="192.0.2.1", receiver_port=9000)
            sender.run()
            snapshot = STATE.snapshot()["state"]
            self.assertEqual(snapshot["status"], "failed")
            self.assertEqual(snapshot["receiver_status"], "Connection Failed")

    def test_configurable_receiver_and_localhost_transfer(self):
        """Receiver bound to 0.0.0.0:9200, sender targets 127.0.0.1:9200"""
        stop_event = threading.Event()
        receiver = UDPReceiver(STATE, host="0.0.0.0", port=9200, stop_event=stop_event)
        receiver.start()
        self.assertTrue(receiver.ready_event.wait(timeout=2.0))

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                path = Path(temp_dir) / "config_transfer.bin"
                content = os.urandom(25 * 1024)
                path.write_bytes(content)
                sender_hash = sha256_file(path)

                sender = ReliableUDPSender(STATE, path, window_size=8, timeout_ms=100, packet_loss=10, receiver_ip="127.0.0.1", receiver_port=9200)
                sender.run()

                snapshot = STATE.snapshot()["state"]
                self.assertEqual(snapshot["status"], "complete")
                self.assertEqual(snapshot["receiver_status"], "Transfer Completed")
                self.assertEqual(snapshot["integrity_status"], "VERIFIED")
                self.assertEqual(snapshot["sender_hash"], sender_hash)
                self.assertEqual(snapshot["receiver_hash"], sender_hash)
                self.assertEqual(snapshot["receiver_ip"], "127.0.0.1")
                self.assertEqual(snapshot["receiver_port"], 9200)
        finally:
            stop_event.set()
            receiver.join(timeout=2.0)

    def test_lan_interface_transfer(self):
        """Receiver bound to 0.0.0.0:9300; sender targets machine's local LAN IP"""
        # Resolve machine's local LAN IP
        try:
            hostname = socket.gethostname()
            lan_ip = socket.gethostbyname(hostname)
        except Exception:
            lan_ip = "127.0.0.1"

        stop_event = threading.Event()
        receiver = UDPReceiver(STATE, host="0.0.0.0", port=9300, stop_event=stop_event)
        receiver.start()
        self.assertTrue(receiver.ready_event.wait(timeout=2.0))

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                path = Path(temp_dir) / "lan_sample.bin"
                content = os.urandom(30 * 1024)
                path.write_bytes(content)
                sender_hash = sha256_file(path)

                sender = ReliableUDPSender(STATE, path, window_size=8, timeout_ms=100, packet_loss=5, receiver_ip=lan_ip, receiver_port=9300)
                sender.run()

                snapshot = STATE.snapshot()["state"]
                self.assertEqual(snapshot["status"], "complete")
                self.assertEqual(snapshot["receiver_status"], "Transfer Completed")
                self.assertEqual(snapshot["integrity_status"], "VERIFIED")
                self.assertEqual(snapshot["sender_hash"], sender_hash)
                self.assertEqual(snapshot["receiver_hash"], sender_hash)
        finally:
            stop_event.set()
            receiver.join(timeout=2.0)

    def test_lost_ready_handshake(self):
        """Verify sender retransmits START if READY is dropped on first attempt"""
        STATE.reset()
        stop_event = threading.Event()
        # Custom receiver socket that drops the first START and only responds to second START
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 9400))
        sock.settimeout(2.0)

        def mock_receiver_loop():
            start_count = 0
            while not stop_event.is_set():
                try:
                    raw, addr = sock.recvfrom(4096)
                    pkt = parse_packet(raw)
                    if pkt.type == START:
                        start_count += 1
                        if start_count == 1:
                            # Drop first START (simulate dropped READY / network loss)
                            continue
                        # Acknowledge second START
                        sock.sendto(make_packet(0, READY), addr)
                    elif pkt.type == DATA:
                        sock.sendto(make_packet(pkt.seq, ACK), addr)
                    elif pkt.type == FIN:
                        expected_hash = hashlib.sha256(b"data1234").hexdigest().encode("ascii")
                        sock.sendto(make_packet(pkt.seq, FIN_ACK, expected_hash), addr)
                        break
                except (socket.timeout, OSError):
                    continue

        t = threading.Thread(target=mock_receiver_loop, daemon=True)
        t.start()

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                path = Path(temp_dir) / "retry.bin"
                path.write_bytes(b"data1234")
                sender = ReliableUDPSender(STATE, path, window_size=4, timeout_ms=100, packet_loss=0, receiver_ip="127.0.0.1", receiver_port=9400)
                sender.run()
                snapshot = STATE.snapshot()["state"]
                # Must succeed because sender retransmitted START
                self.assertEqual(snapshot["status"], "complete")
                self.assertEqual(snapshot["receiver_status"], "Transfer Completed")
        finally:
            stop_event.set()
            sock.close()
            t.join(timeout=2.0)


if __name__ == "__main__":
    unittest.main()
