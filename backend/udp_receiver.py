import math
import socket
import sys
import threading
import time
from pathlib import Path

from config import PAYLOAD_SIZE, RECEIVED_DIR, UDP_HOST, UDP_PORT
from integrity import sha256_file
from protocol import ACK, DATA, FIN, FIN_ACK, READY, START, decode_metadata, make_packet, parse_packet


WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}


def sanitize_filename(name: str) -> str:
    base = Path(name).name.strip().replace("\x00", "")
    safe = "".join(ch if ch.isalnum() or ch in " ._-()" else "_" for ch in base).strip(". ")
    if not safe or safe in (".", "..") or all(c in "._ " for c in safe):
        return "received_file.bin"
    stem = safe.split(".")[0].upper()
    if stem in WINDOWS_RESERVED:
        safe = f"safe_{safe}"
    return safe


class UDPReceiver(threading.Thread):
    def __init__(self, state, host="0.0.0.0", port=UDP_PORT, stop_event=None):
        super().__init__(daemon=True)
        self.state = state
        self.host = host
        self.port = int(port)
        self.stop_event = stop_event or threading.Event()
        self.ready_event = threading.Event()
        self.done_event = threading.Event()
        self.error = None
        self.output_path = None
        self.receiver_hash = ""
        self.session_id = None

    def run(self):
        chunks = {}
        out_of_order_chunks = {}
        output_file = None
        expected_packets = None
        filename = None
        file_size = 0
        highest_written = -1
        sender_addr = None

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if sys.platform == "win32" and hasattr(socket, "SIO_UDP_CONNRESET"):
                    try:
                        sock.ioctl(socket.SIO_UDP_CONNRESET, False)
                    except Exception:
                        pass
                sock.bind((self.host, self.port))
                sock.settimeout(0.2)
                self.ready_event.set()
                self.state.event("RECEIVER_READY", detail=f"Listening on UDP {self.port}")
                self.state.record_telemetry("receiver", "RECEIVER_READY", status="success", detail=f"Listening on UDP {self.port}")

                while not self.stop_event.is_set():
                    try:
                        raw, addr = sock.recvfrom(PAYLOAD_SIZE + 4096)
                    except socket.timeout:
                        continue
                    except (ConnectionResetError, OSError):
                        continue

                    try:
                        packet = parse_packet(raw)
                    except Exception as exc:
                        self.state.increment(malformed_packets=1)
                        self.state.event("MALFORMED", detail=str(exc), status="error")
                        self.state.record_telemetry(
                            "receiver", "MALFORMED", status="error", detail=str(exc)
                        )
                        continue

                    if packet.type == START:
                        try:
                            announced = decode_metadata(packet.payload)
                            self.state.begin_receiver_telemetry(announced.get("session_id"))
                        except Exception:
                            pass

                    self.state.record_telemetry(
                        "receiver",
                        "RECEIVED",
                        packet.type_name,
                        packet.seq,
                        packet.length,
                        packet.crc32,
                        packet.valid_crc,
                        "success" if packet.valid_crc else "error",
                        detail="Incoming UDP packet",
                    )

                    if not packet.valid_crc:
                        self.state.increment(crc_errors=1)
                        self.state.event("CRC_REJECT", packet.seq, "CRC32 mismatch", "error")
                        self.state.record_telemetry(
                            "receiver", "CRC_REJECT", packet.type_name, packet.seq,
                            packet.length, packet.crc32, False, "error",
                            detail="CRC32 mismatch",
                        )
                        continue

                    if packet.type == START:
                        sender_addr = addr
                        metadata = decode_metadata(packet.payload)
                        incoming_session = metadata.get("session_id")
                        self.state.begin_receiver_telemetry(incoming_session)
                        self.state.record_telemetry(
                            "receiver", "START_RECEIVED", "START", packet.seq,
                            packet.length, packet.crc32, packet.valid_crc,
                            "success", detail="Transfer handshake received",
                        )

                        # Handle duplicate START in active session idempotently
                        if self.session_id and incoming_session and incoming_session == self.session_id:
                            ready_packet = make_packet(0, READY)
                            ready = parse_packet(ready_packet)
                            sock.sendto(ready_packet, addr)
                            self.state.event("READY_RETRY", detail="Resent READY for duplicate START", status="info")
                            self.state.record_telemetry(
                                "receiver", "READY_SENT", "READY", ready.seq, ready.length,
                                ready.crc32, ready.valid_crc, "info",
                                detail="Duplicate START",
                            )
                            continue

                        # New session initialization
                        self.session_id = incoming_session
                        filename = sanitize_filename(metadata.get("filename", "received_file.bin"))
                        file_size = int(metadata.get("file_size", 0))
                        expected_packets = int(metadata.get("total_packets", math.ceil(file_size / PAYLOAD_SIZE) if file_size > 0 else 0))

                        if output_file:
                            try:
                                output_file.close()
                            except Exception:
                                pass
                            output_file = None

                        chunks.clear()
                        out_of_order_chunks.clear()
                        highest_written = -1

                        target = RECEIVED_DIR / filename
                        suffix = 1
                        while target.exists():
                            stem = Path(filename).stem
                            ext = Path(filename).suffix
                            target = RECEIVED_DIR / f"{stem}_{suffix}{ext}"
                            suffix += 1
                        self.output_path = target
                        output_file = self.output_path.open("wb")

                        ready_packet = make_packet(0, READY)
                        ready = parse_packet(ready_packet)
                        sock.sendto(ready_packet, addr)
                        self.state.update(status="transferring", message="Handshake complete: receiver sent READY")
                        self.state.event("READY", detail=f"Receiving {filename}", status="success")
                        self.state.record_telemetry(
                            "receiver", "READY_SENT", "READY", ready.seq, ready.length,
                            ready.crc32, ready.valid_crc, "success",
                            detail=f"Receiving {filename}",
                        )
                        continue

                    if packet.type == DATA:
                        if expected_packets is None or output_file is None:
                            continue

                        # Check if packet was already written to disk or already buffered
                        duplicate = (packet.seq <= highest_written) or (packet.seq in out_of_order_chunks)
                        if duplicate:
                            self.state.increment(duplicates=1)
                            self.state.event("DUPLICATE", packet.seq, "ACK repeated", "warn")
                            self.state.record_telemetry(
                                "receiver", "DUPLICATE", "DATA", packet.seq,
                                packet.length, packet.crc32, packet.valid_crc,
                                "warn", detail="Duplicate DATA packet",
                            )
                        else:
                            self.state.increment(packets_received=1)
                            if packet.seq == highest_written + 1:
                                output_file.write(packet.payload)
                                highest_written += 1
                                self.state.event("DATA", packet.seq, f"{packet.length} bytes received", "success")
                                while (highest_written + 1) in out_of_order_chunks:
                                    buffered_payload = out_of_order_chunks.pop(highest_written + 1)
                                    output_file.write(buffered_payload)
                                    highest_written += 1
                            else:
                                out_of_order_chunks[packet.seq] = packet.payload
                                self.state.increment(out_of_order=1)
                                self.state.event("OUT_OF_ORDER", packet.seq, "Stored for reassembly", "warn")
                                self.state.record_telemetry(
                                    "receiver", "OUT_OF_ORDER", "DATA", packet.seq,
                                    packet.length, packet.crc32, packet.valid_crc,
                                    "warn", detail="Stored for reassembly",
                                )

                        ack_packet = make_packet(packet.seq, ACK)
                        ack = parse_packet(ack_packet)
                        sock.sendto(ack_packet, addr)
                        self.state.record_telemetry(
                            "receiver", "ACK_SENT", "ACK", ack.seq, ack.length,
                            ack.crc32, ack.valid_crc, "success", detail="ACK sent",
                        )
                        continue

                    if packet.type == FIN:
                        self.state.record_telemetry(
                            "receiver", "FIN_RECEIVED", "FIN", packet.seq,
                            packet.length, packet.crc32, packet.valid_crc,
                            "success", detail="FIN received",
                        )
                        if expected_packets is None:
                            continue
                        if highest_written + 1 < expected_packets or out_of_order_chunks:
                            missing_count = expected_packets - (highest_written + 1)
                            self.state.event("FIN_WAIT", detail=f"Missing {missing_count} packets", status="warn")
                            continue

                        if output_file:
                            output_file.flush()
                            output_file.close()
                            output_file = None

                        if self.output_path and self.output_path.exists():
                            with self.output_path.open("a+b") as file:
                                file.truncate(file_size)
                            self.receiver_hash = sha256_file(self.output_path)
                        else:
                            self.receiver_hash = ""

                        fin_ack_packet = make_packet(packet.seq, FIN_ACK, self.receiver_hash.encode("ascii"))
                        fin_ack = parse_packet(fin_ack_packet)
                        sock.sendto(fin_ack_packet, addr)
                        self.state.event("FIN_ACK", detail="Reassembled file and sent FIN_ACK", status="success")
                        self.state.record_telemetry(
                            "receiver", "FIN_ACK_SENT", "FIN_ACK", fin_ack.seq,
                            fin_ack.length, fin_ack.crc32, fin_ack.valid_crc, "success",
                            detail="Reassembled file and sent FIN_ACK",
                        )
                        self.done_event.set()

                        # TIME_WAIT linger phase to re-send FIN_ACK if sender's FIN was retransmitted
                        linger_deadline = time.time() + 1.5
                        while not self.stop_event.is_set() and time.time() < linger_deadline:
                            try:
                                raw, client_addr = sock.recvfrom(PAYLOAD_SIZE + 4096)
                                dup_fin = parse_packet(raw)
                                if dup_fin.valid_crc and dup_fin.type == FIN:
                                    sock.sendto(fin_ack_packet, client_addr)
                                    self.state.event("FIN_ACK_RETRY", detail="Resent FIN_ACK to sender", status="warn")
                            except (socket.timeout, ConnectionResetError, OSError):
                                continue
                            except Exception:
                                continue

                        # Reset session variables so receiver remains listening for subsequent transfers
                        expected_packets = None
                        highest_written = -1
                        out_of_order_chunks.clear()
                        chunks.clear()
                        continue

        except Exception as exc:
            self.error = str(exc)
            self.ready_event.set()
            self.state.fail(f"Receiver error: {exc}")
        finally:
            if output_file:
                try:
                    output_file.close()
                except Exception:
                    pass


if __name__ == "__main__":
    import argparse
    from state import STATE

    parser = argparse.ArgumentParser(description="Reliable UDP File Receiver")
    parser.add_argument("--host", default="0.0.0.0", help="Listening IP interface (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=UDP_PORT, help=f"Listening UDP port (default: {UDP_PORT})")
    args = parser.parse_args()

    print(f"Starting standalone UDP Receiver on {args.host}:{args.port}...")
    print(f"Destination folder: {RECEIVED_DIR.resolve()}")
    receiver = UDPReceiver(STATE, host=args.host, port=args.port)
    receiver.start()
    receiver.ready_event.wait(timeout=2.0)
    print("Receiver is online and waiting for incoming UDP transfers. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping receiver...")
        receiver.stop_event.set()
        receiver.join(timeout=2.0)
        print("Receiver stopped.")
