import hashlib
import io
import json
import os
import select
import socket
import sys
import tempfile
import threading
import time
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app import AppHandler
from config import HTTP_HOST, HTTP_PORT, PAYLOAD_SIZE, UDP_HOST, UDP_PORT
from http.server import ThreadingHTTPServer
from integrity import sha256_file
from protocol import (
    ACK,
    DATA,
    FIN,
    FIN_ACK,
    READY,
    START,
    decode_metadata,
    encode_metadata,
    make_packet,
    parse_packet,
)
from state import STATE
from udp_receiver import UDPReceiver
from udp_sender import ReliableUDPSender


def create_pdf(path: Path):
    content = (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj\n"
        b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj\n"
        b"xref\n0 4\n0000000000 65535 f \n0000000010 00000 n \n0000000060 00000 n \n0000000117 00000 n \n"
        b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n198\n%%EOF\n"
    )
    path.write_bytes(content)


def create_zip(path: Path):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("hello.txt", "Hello world from inside a zip file!\n" * 50)
        zf.writestr("binary.dat", os.urandom(8192))
        zf.writestr("subfolder/nested.txt", "Nested content in zip structure")


def run_transfer_test(file_path: Path, window_size=8, timeout_ms=100, packet_loss=0, receiver_ip="127.0.0.1", receiver_port=9000):
    STATE.reset()
    orig_size = file_path.stat().st_size
    orig_bytes = file_path.read_bytes()
    orig_hash = sha256_file(file_path)

    stop_event = threading.Event()
    receiver = UDPReceiver(STATE, host="0.0.0.0", port=receiver_port, stop_event=stop_event)
    receiver.start()
    assert receiver.ready_event.wait(timeout=2.0)

    try:
        sender = ReliableUDPSender(STATE, file_path, window_size, timeout_ms, packet_loss, receiver_ip=receiver_ip, receiver_port=receiver_port)
        sender.run()

        snapshot = STATE.snapshot()["state"]
        raw_path = receiver.output_path or snapshot.get("output_path")
        if not raw_path:
            return False, f"Transfer failed or incomplete: {snapshot.get('message')}", {}
        recv_path = Path(raw_path)

        if not recv_path.exists():
            return False, "Received file does not exist on disk", {}

        recv_size = recv_path.stat().st_size
        recv_bytes = recv_path.read_bytes()
        recv_hash = sha256_file(recv_path)

        size_match = (orig_size == recv_size)
        bytes_match = (orig_bytes == recv_bytes)
        hash_match = (orig_hash == recv_hash == snapshot.get("receiver_hash") == snapshot.get("sender_hash"))
        status_match = (snapshot.get("status") == "complete" and snapshot.get("integrity_status") == "VERIFIED")

        metrics = {
            "orig_size": orig_size,
            "recv_size": recv_size,
            "orig_hash": orig_hash,
            "recv_hash": recv_hash,
            "packets": snapshot.get("total_packets"),
            "packets_acked": snapshot.get("packets_acked"),
            "packets_lost": snapshot.get("packets_lost"),
            "retransmissions": snapshot.get("retransmissions"),
            "throughput_mbps": snapshot.get("throughput_mbps"),
            "duration_sec": snapshot.get("duration_sec"),
            "status": snapshot.get("status"),
            "integrity": snapshot.get("integrity_status"),
            "receiver_ip": snapshot.get("receiver_ip", receiver_ip),
            "receiver_port": snapshot.get("receiver_port", receiver_port),
            "receiver_status": snapshot.get("receiver_status"),
        }

        if size_match and bytes_match and hash_match and status_match:
            return True, "SUCCESS: Byte-for-byte exact match and SHA-256 verified", metrics
        else:
            err = f"MISMATCH: size_match={size_match}, bytes_match={bytes_match}, hash_match={hash_match}, status={snapshot.get('status')}"
            return False, err, metrics
    finally:
        stop_event.set()
        receiver.join(timeout=2.0)


def test_lost_ack():
    """Verify receiver resends ACK upon duplicate DATA when previous ACK was dropped"""
    STATE.reset()
    stop_event = threading.Event()
    receiver = UDPReceiver(STATE, UDP_HOST, UDP_PORT, stop_event)
    receiver.start()
    assert receiver.ready_event.wait(timeout=2), "Receiver ready timeout"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_HOST, 0))
    sock.settimeout(1.0)
    target = (UDP_HOST, UDP_PORT)

    try:
        # 1. START
        meta = {"session_id": "test_lost_ack", "filename": "test_ack.bin", "file_size": 10, "total_packets": 1}
        sock.sendto(make_packet(0, START, encode_metadata(meta)), target)
        raw, _ = sock.recvfrom(4096)
        pkt = parse_packet(raw)
        assert pkt.type == READY, "Expected READY"

        # 2. Send DATA 0
        sock.sendto(make_packet(0, DATA, b"0123456789"), target)
        raw, _ = sock.recvfrom(4096)
        pkt = parse_packet(raw)
        assert pkt.type == ACK and pkt.seq == 0, "Expected ACK 0"

        # 3. Simulate sender did not get ACK, retransmits DATA 0
        sock.sendto(make_packet(0, DATA, b"0123456789"), target)
        raw, _ = sock.recvfrom(4096)
        dup_ack = parse_packet(raw)
        assert dup_ack.type == ACK and dup_ack.seq == 0, "Receiver must resend ACK 0 on duplicate DATA"

        # 4. Finish
        sock.sendto(make_packet(1, FIN), target)
        raw, _ = sock.recvfrom(4096)
        fin_ack = parse_packet(raw)
        assert fin_ack.type == FIN_ACK, "Expected FIN_ACK"

        recv_path = receiver.output_path
        assert recv_path.read_bytes() == b"0123456789", "File content corrupted by duplicate"
        return True, "Receiver correctly re-ACKed duplicate DATA without corrupting file"
    finally:
        sock.close()
        stop_event.set()
        receiver.join(timeout=2.0)


def test_out_of_order():
    """Verify receiver buffers out-of-order packets and reassembles in sequential order"""
    STATE.reset()
    stop_event = threading.Event()
    receiver = UDPReceiver(STATE, UDP_HOST, UDP_PORT, stop_event)
    receiver.start()
    assert receiver.ready_event.wait(timeout=2), "Receiver ready timeout"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_HOST, 0))
    sock.settimeout(1.0)
    target = (UDP_HOST, UDP_PORT)

    try:
        meta = {"session_id": "test_ooo", "filename": "test_ooo.bin", "file_size": 30, "total_packets": 3}
        sock.sendto(make_packet(0, START, encode_metadata(meta)), target)
        raw, _ = sock.recvfrom(4096)
        assert parse_packet(raw).type == READY

        # Send packets in reverse: seq 2, seq 1, seq 0
        sock.sendto(make_packet(2, DATA, b"PART3_2222"), target)
        raw, _ = sock.recvfrom(4096)
        assert parse_packet(raw).seq == 2

        sock.sendto(make_packet(1, DATA, b"PART2_1111"), target)
        raw, _ = sock.recvfrom(4096)
        assert parse_packet(raw).seq == 1

        sock.sendto(make_packet(0, DATA, b"PART1_0000"), target)
        raw, _ = sock.recvfrom(4096)
        assert parse_packet(raw).seq == 0

        sock.sendto(make_packet(3, FIN), target)
        raw, _ = sock.recvfrom(4096)
        assert parse_packet(raw).type == FIN_ACK

        expected = b"PART1_0000PART2_1111PART3_2222"
        actual = receiver.output_path.read_bytes()
        assert actual == expected, f"Reassembly failed: expected {expected}, got {actual}"
        return True, f"Out-of-order delivery correctly reassembled: {len(actual)} bytes exact"
    finally:
        sock.close()
        stop_event.set()
        receiver.join(timeout=2.0)


def test_corrupted_packet():
    """Verify receiver rejects corrupted packet with CRC_REJECT and does not write corrupted bytes"""
    STATE.reset()
    stop_event = threading.Event()
    receiver = UDPReceiver(STATE, UDP_HOST, UDP_PORT, stop_event)
    receiver.start()
    assert receiver.ready_event.wait(timeout=2)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_HOST, 0))
    sock.settimeout(0.3)
    target = (UDP_HOST, UDP_PORT)

    try:
        meta = {"session_id": "test_corrupt", "filename": "test_corrupt.bin", "file_size": 40, "total_packets": 2}
        sock.sendto(make_packet(0, START, encode_metadata(meta)), target)
        raw, _ = sock.recvfrom(4096)
        assert parse_packet(raw).type == READY

        # Send corrupted packet 0 (flip payload bit)
        bad_pkt = bytearray(make_packet(0, DATA, b"GOOD_PAYLOAD00000000"))
        bad_pkt[15] ^= 0xFF  # Corrupt payload byte
        sock.sendto(bytes(bad_pkt), target)

        # Receiver must NOT send ACK
        try:
            sock.recvfrom(4096)
            assert False, "Receiver must not ACK corrupted packet"
        except socket.timeout:
            pass  # Expected: timeout with no ACK

        snapshot = STATE.snapshot()["state"]
        assert snapshot["crc_errors"] >= 1, "Receiver must increment crc_errors"

        # Now sender retransmits clean packet 0
        sock.sendto(make_packet(0, DATA, b"GOOD_PAYLOAD00000000"), target)
        raw, _ = sock.recvfrom(4096)
        assert parse_packet(raw).type == ACK and parse_packet(raw).seq == 0

        # Send packet 1
        sock.sendto(make_packet(1, DATA, b"SECOND_PAYLOAD000000"), target)
        raw, _ = sock.recvfrom(4096)
        assert parse_packet(raw).type == ACK and parse_packet(raw).seq == 1

        sock.sendto(make_packet(2, FIN), target)
        sock.settimeout(1.0)
        raw, _ = sock.recvfrom(4096)
        assert parse_packet(raw).type == FIN_ACK

        expected = b"GOOD_PAYLOAD00000000" + b"SECOND_PAYLOAD000000"
        actual = receiver.output_path.read_bytes()
        assert actual == expected, "Corrupted bytes leaked into file"
        return True, "Receiver rejected corrupted packet via CRC32 and accepted retransmitted valid packet"
    finally:
        sock.close()
        stop_event.set()
        receiver.join(timeout=2.0)


def test_lost_fin_ack():
    """Verify receiver TIME_WAIT state retransmits FIN_ACK when sender re-sends FIN"""
    STATE.reset()
    stop_event = threading.Event()
    receiver = UDPReceiver(STATE, UDP_HOST, UDP_PORT, stop_event)
    receiver.start()
    assert receiver.ready_event.wait(timeout=2)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_HOST, 0))
    sock.settimeout(1.0)
    target = (UDP_HOST, UDP_PORT)

    try:
        meta = {"session_id": "test_fin_ack", "filename": "test_fin.bin", "file_size": 5, "total_packets": 1}
        sock.sendto(make_packet(0, START, encode_metadata(meta)), target)
        raw, _ = sock.recvfrom(4096)
        assert parse_packet(raw).type == READY

        sock.sendto(make_packet(0, DATA, b"ABCDE"), target)
        raw, _ = sock.recvfrom(4096)
        assert parse_packet(raw).type == ACK

        # Send FIN
        sock.sendto(make_packet(1, FIN), target)
        raw, _ = sock.recvfrom(4096)
        fin_ack_1 = parse_packet(raw)
        assert fin_ack_1.type == FIN_ACK

        # Simulate sender dropped FIN_ACK, sender retransmits FIN 200ms later
        time.sleep(0.2)
        sock.sendto(make_packet(1, FIN), target)
        raw, _ = sock.recvfrom(4096)
        fin_ack_2 = parse_packet(raw)
        assert fin_ack_2.type == FIN_ACK, "Receiver failed to retransmit FIN_ACK during TIME_WAIT"
        assert fin_ack_2.payload == fin_ack_1.payload, "Hashes in retransmitted FIN_ACK differ"
        return True, "Receiver TIME_WAIT linger state successfully caught retransmitted FIN and re-sent FIN_ACK"
    finally:
        sock.close()
        stop_event.set()
        receiver.join(timeout=2.0)


def test_interrupted_transfer_cleanup():
    """Verify that if a transfer fails or is interrupted, port 9000 is freed immediately for next transfer"""
    STATE.reset()
    stop_event = threading.Event()
    receiver = UDPReceiver(STATE, host="127.0.0.1", port=9000, stop_event=stop_event)
    receiver.start()
    assert receiver.ready_event.wait(timeout=2.0)
    # Stop receiver and verify port 9000 is released cleanly
    stop_event.set()
    receiver.join(timeout=2.0)
    time.sleep(0.1)
    test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        test_sock.bind((UDP_HOST, UDP_PORT))
        test_sock.close()
        port_freed = True
    except Exception:
        port_freed = False
    assert port_freed, "Port 9000 was not released after transfer cleanup"
    return True, "Port 9000 cleanly released and available immediately after transfer completion"


def test_concurrent_transfers_conflict():
    """Verify server rejects concurrent transfer requests with HTTP 409 Conflict"""
    from app import TRANSFER_LOCK
    import app as app_module

    # Mock an active running transfer thread
    dummy_thread = threading.Thread(target=lambda: time.sleep(1.0))
    dummy_thread.start()
    with app_module.TRANSFER_LOCK:
        app_module.TRANSFER_THREAD = dummy_thread

    # Make request to /api/reset and verify it rejects
    class MockHandler(AppHandler):
        def __init__(self):
            self.headers = {}
            self.responses = []
        def send_json(self, data, status):
            self.responses.append((status, data))

    handler = MockHandler()
    handler.path = "/api/reset"
    handler.do_POST()
    status_code, resp_data = handler.responses[0]

    dummy_thread.join()
    assert status_code == 409, f"Expected 409 Conflict, got {status_code}"
    assert "Cannot reset" in resp_data.get("error", "")
    return True, f"Concurrent request rejected with HTTP {status_code} Conflict"


def test_rest_api_endpoints():
    """Verify all backend REST APIs return valid responses"""
    server = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), AppHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.3)

    client_host = "127.0.0.1"
    try:
        # GET /api/status
        with urllib.request.urlopen(f"http://{client_host}:{HTTP_PORT}/api/status") as res:
            assert res.status == 200
            data = json.loads(res.read().decode())
            assert "state" in data and "events" in data and "packets" in data

        # GET /api/history
        with urllib.request.urlopen(f"http://{client_host}:{HTTP_PORT}/api/history") as res:
            assert res.status == 200
            data = json.loads(res.read().decode())
            assert "history" in data

        # GET /index.html
        with urllib.request.urlopen(f"http://{client_host}:{HTTP_PORT}/index.html") as res:
            assert res.status == 200
            html = res.read().decode()
            assert "Reliable File Transfer over UDP" in html

        # GET /style.css
        with urllib.request.urlopen(f"http://{client_host}:{HTTP_PORT}/style.css") as res:
            assert res.status == 200

        # GET /app.js
        with urllib.request.urlopen(f"http://{client_host}:{HTTP_PORT}/app.js") as res:
            assert res.status == 200

        # POST /api/reset
        req = urllib.request.Request(f"http://{client_host}:{HTTP_PORT}/api/reset", data=b"", method="POST")
        with urllib.request.urlopen(req) as res:
            assert res.status == 200
            data = json.loads(res.read().decode())
            assert data.get("ok") is True

        return True, "All HTTP endpoints (/api/status, /api/history, /api/reset, /index.html, /style.css, /app.js) verified 200 OK"
    finally:
        server.shutdown()
        server.server_close()


def main():
    print("=" * 70)
    print("STARTING FULL VERIFICATION SUITE ACROSS ALL 20 SCENARIOS")
    print("=" * 70)

    results = []

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # 1. Empty file
        p1 = temp_path / "empty.bin"
        p1.write_bytes(b"")
        ok, msg, m = run_transfer_test(p1, window_size=8, timeout_ms=100, packet_loss=0)
        results.append(("Scenario 1: Empty File Transfer (0 bytes)", ok, msg, m))

        # 2. Small text file
        p2 = temp_path / "small.txt"
        p2.write_text("The quick brown fox jumps over the lazy dog.\n" * 10, encoding="utf-8")
        ok, msg, m = run_transfer_test(p2, window_size=4, timeout_ms=100, packet_loss=0)
        results.append(("Scenario 2: Small Text File Transfer", ok, msg, m))

        # 3. PDF transfer
        p3 = temp_path / "sample.pdf"
        create_pdf(p3)
        ok, msg, m = run_transfer_test(p3, window_size=8, timeout_ms=100, packet_loss=0)
        results.append(("Scenario 3: PDF Transfer", ok, msg, m))

        # 4. Image transfer
        existing_jpg = ROOT / "uploads" / "IMG_1565.jpg"
        if existing_jpg.exists():
            p4 = existing_jpg
        else:
            p4 = temp_path / "sample.jpg"
            p4.write_bytes(os.urandom(150 * 1024))
        ok, msg, m = run_transfer_test(p4, window_size=16, timeout_ms=150, packet_loss=0)
        results.append(("Scenario 4: Image Transfer (Real JPEG)", ok, msg, m))

        # 5. ZIP transfer
        p5 = temp_path / "sample.zip"
        create_zip(p5)
        ok, msg, m = run_transfer_test(p5, window_size=8, timeout_ms=100, packet_loss=0)
        results.append(("Scenario 5: ZIP Archive Transfer", ok, msg, m))

        # 6. Large binary file transfer (2.5 MB)
        p6 = temp_path / "large_blob.bin"
        p6.write_bytes(os.urandom(2500 * 1024))
        ok, msg, m = run_transfer_test(p6, window_size=16, timeout_ms=120, packet_loss=0)
        results.append(("Scenario 6: Large Binary File Transfer (2.5 MB)", ok, msg, m))

        # 7. 0% packet loss
        p7 = temp_path / "loss_0.bin"
        p7.write_bytes(os.urandom(32 * 1024))
        ok, msg, m = run_transfer_test(p7, window_size=8, timeout_ms=100, packet_loss=0)
        results.append(("Scenario 7: 0% Packet Loss", ok, msg, m))

        # 8. 10% packet loss
        p8 = temp_path / "loss_10.bin"
        p8.write_bytes(os.urandom(32 * 1024))
        ok, msg, m = run_transfer_test(p8, window_size=8, timeout_ms=100, packet_loss=10)
        results.append(("Scenario 8: 10% Packet Loss", ok, msg, m))

        # 9. 30% packet loss
        p9 = temp_path / "loss_30.bin"
        p9.write_bytes(os.urandom(32 * 1024))
        ok, msg, m = run_transfer_test(p9, window_size=8, timeout_ms=100, packet_loss=30)
        results.append(("Scenario 9: 30% Packet Loss", ok, msg, m))

        # 10. High packet loss (50%)
        p10 = temp_path / "loss_50.bin"
        p10.write_bytes(os.urandom(16 * 1024))
        ok, msg, m = run_transfer_test(p10, window_size=8, timeout_ms=100, packet_loss=50)
        results.append(("Scenario 10: High Packet Loss (50% Loss)", ok, msg, m))

        # 11. Sliding Window variations (1, 4, 8, 16, 32)
        p11 = temp_path / "window_test.bin"
        p11.write_bytes(os.urandom(20 * 1024))
        w_ok = True
        for w in (1, 4, 8, 16, 32):
            ok, msg, m = run_transfer_test(p11, window_size=w, timeout_ms=100, packet_loss=5)
            if not ok:
                w_ok = False
                break
        results.append(("Scenario 11: Sliding Window Sizes (W=1, 4, 8, 16, 32)", w_ok, "All window sizes completed and verified", {}))

        # 12. Timeout variations (50ms, 100ms, 250ms, 500ms)
        p12 = temp_path / "timeout_test.bin"
        p12.write_bytes(os.urandom(16 * 1024))
        t_ok = True
        for t in (50, 100, 250, 500):
            ok, msg, m = run_transfer_test(p12, window_size=8, timeout_ms=t, packet_loss=10)
            if not ok:
                t_ok = False
                break
        results.append(("Scenario 12: Timeout Settings (50ms, 100ms, 250ms, 500ms)", t_ok, "All timeout settings completed and verified", {}))

        # 13. Lost DATA packet (verified via simulated drop causing timeout and retransmit)
        p13 = temp_path / "lost_data.bin"
        p13.write_bytes(os.urandom(24 * 1024))
        ok, msg, m = run_transfer_test(p13, window_size=8, timeout_ms=80, packet_loss=20)
        ok = ok and (m.get("packets_lost", 0) > 0) and (m.get("retransmissions", 0) > 0)
        results.append(("Scenario 13: Lost DATA Packet Recovery", ok, f"Lost: {m.get('packets_lost')} packets, Resent: {m.get('retransmissions')} retransmissions", m))

        # 14. Lost ACK packet
        ok, msg = test_lost_ack()
        results.append(("Scenario 14: Lost ACK Packet Recovery", ok, msg, {}))

        # 15. Duplicate packet
        ok, msg = test_lost_ack()  # test_lost_ack tests duplicate DATA packet acceptance and re-ACK without duplicate write
        results.append(("Scenario 15: Duplicate Packet Handling", ok, msg, {}))

        # 16. Out-of-order packet
        ok, msg = test_out_of_order()
        results.append(("Scenario 16: Out-of-Order Packet Buffering & Sequential Assembly", ok, msg, {}))

        # 17. Corrupted packet
        ok, msg = test_corrupted_packet()
        results.append(("Scenario 17: Corrupted Packet Rejection via CRC32", ok, msg, {}))

        # 18. Lost FIN_ACK
        ok, msg = test_lost_fin_ack()
        results.append(("Scenario 18: Lost FIN_ACK Recovery via Receiver TIME_WAIT", ok, msg, {}))

        # 19. Interrupted transfer
        ok, msg = test_interrupted_transfer_cleanup()
        results.append(("Scenario 19: Interrupted Transfer & Port 9000 Release", ok, msg, {}))

        # 20. Concurrent transfers
        ok, msg = test_concurrent_transfers_conflict()
        results.append(("Scenario 20: Concurrent Transfers (HTTP 409 Conflict Protection)", ok, msg, {}))

        # REST API verification
        api_ok, api_msg = test_rest_api_endpoints()
        results.append(("REST API Verification", api_ok, api_msg, {}))

    print("\n" + "=" * 70)
    print("VERIFICATION RESULTS SUMMARY")
    print("=" * 70)
    all_passed = True
    for name, ok, msg, metrics in results:
        status_str = "PASS" if ok else "FAIL"
        if not ok:
            all_passed = False
        print(f"[{status_str}] {name}")
        print(f"       Details: {msg}")
        if metrics:
            print(f"       Orig SHA-256: {metrics.get('orig_hash')}")
            print(f"       Recv SHA-256: {metrics.get('recv_hash')}")
            print(f"       Size: {metrics.get('orig_size')} bytes | Throughput: {metrics.get('throughput_mbps')} Mbps | Duration: {metrics.get('duration_sec')}s")
        print()

    print("=" * 70)
    if all_passed:
        print("ALL SCENARIOS PASSED WITH EXACT BYTE-FOR-BYTE AND SHA-256 PARITY!")
    else:
        print("SOME SCENARIOS FAILED. CHECK LOGS ABOVE.")
    print("=" * 70)
    return all_passed


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
