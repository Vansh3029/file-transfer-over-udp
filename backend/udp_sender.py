import math
import mimetypes
import random
import select
import socket
import sys
import threading
import time
import uuid
from pathlib import Path

from config import DEFAULT_RECEIVER_IP, DEFAULT_RECEIVER_PORT, PAYLOAD_SIZE, UDP_HOST, UDP_PORT
from integrity import sha256_file
from protocol import ACK, FIN, FIN_ACK, READY, START, DATA, HEADER_SIZE, encode_metadata, make_packet, parse_packet
from udp_receiver import UDPReceiver


class ReliableUDPSender:
    def __init__(
        self,
        state,
        file_path: Path,
        window_size: int,
        timeout_ms: int,
        packet_loss: int,
        receiver_ip: str = DEFAULT_RECEIVER_IP,
        receiver_port: int = DEFAULT_RECEIVER_PORT,
        spawn_local_receiver: bool = False,
    ):
        self.state = state
        self.file_path = file_path
        self.window_size = int(window_size)
        self.timeout = max(0.025, int(timeout_ms) / 1000)
        self.packet_loss = int(packet_loss)
        self.receiver_ip = str(receiver_ip).strip() or DEFAULT_RECEIVER_IP
        self.receiver_port = int(receiver_port)
        self.spawn_local_receiver = bool(spawn_local_receiver)
        self.session_id = uuid.uuid4().hex[:12]
        self.receiver = None

    def run(self):
        file_size = self.file_path.stat().st_size
        total_packets = math.ceil(file_size / PAYLOAD_SIZE) if file_size > 0 else 0
        sender_hash = sha256_file(self.file_path)
        mime_type = mimetypes.guess_type(self.file_path.name)[0] or "application/octet-stream"

        self.state.begin(
            self.file_path.name,
            file_size,
            mime_type,
            total_packets,
            self.window_size,
            int(self.timeout * 1000),
            self.packet_loss,
            sender_hash,
            udp_port=self.receiver_port,
            receiver_ip=self.receiver_ip,
            receiver_port=self.receiver_port,
            transfer_id=self.session_id,
        )

        if self.spawn_local_receiver:
            stop_event = threading.Event()
            self.receiver = UDPReceiver(self.state, self.receiver_ip, self.receiver_port, stop_event)
            self.receiver.start()
            if not self.receiver.ready_event.wait(timeout=3):
                self.state.fail("Local receiver did not start")
                return
            if self.receiver.error:
                self.state.fail(self.receiver.error)
                return

        acked = set()
        sent_at = {}
        retries = {}
        packet_cache = {}
        base = 0
        next_seq = 0

        file_handle = None
        try:
            if file_size > 0:
                file_handle = self.file_path.open("rb")

            def get_packet(seq_num: int) -> bytes:
                if seq_num in packet_cache:
                    return packet_cache[seq_num]
                if file_handle is None:
                    chunk = b""
                else:
                    file_handle.seek(seq_num * PAYLOAD_SIZE)
                    chunk = file_handle.read(PAYLOAD_SIZE)
                pkt = make_packet(seq_num, DATA, chunk)
                packet_cache[seq_num] = pkt
                return pkt

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                if sys.platform == "win32" and hasattr(socket, "SIO_UDP_CONNRESET"):
                    try:
                        sock.ioctl(socket.SIO_UDP_CONNRESET, False)
                    except Exception:
                        pass
                sock.bind(("0.0.0.0", 0))
                sock.setblocking(False)
                receiver_addr = (self.receiver_ip, self.receiver_port)

                self._handshake(sock, receiver_addr, file_size, total_packets, sender_hash)
                self.state.set_receiver_status("Transfer in Progress")
                self.state.update(status="transferring", message=f"Sliding-window transfer to {self.receiver_ip}:{self.receiver_port}")

                while len(acked) < total_packets:
                    now = time.time()

                    # Send new packets within sliding window
                    while next_seq < total_packets and next_seq < base + self.window_size:
                        raw_packet = get_packet(next_seq)
                        self._send_data(sock, receiver_addr, next_seq, raw_packet, retransmit=False)
                        sent_at[next_seq] = now
                        next_seq += 1

                    # Non-blocking drain of all queued ACKs
                    timeout_wait = min(0.01, self.timeout / 4)
                    ready, _, _ = select.select([sock], [], [], timeout_wait)
                    if ready:
                        while True:
                            try:
                                raw, _ = sock.recvfrom(4096)
                                packet = parse_packet(raw)
                                self.state.record_telemetry(
                                    "sender", "ACK_RECEIVED", packet.type_name,
                                    packet.seq, packet.length, packet.crc32,
                                    packet.valid_crc, "success" if packet.valid_crc else "error",
                                    detail="Incoming ACK packet",
                                )
                                if packet.valid_crc and packet.type == ACK:
                                    if packet.seq not in acked and packet.seq < total_packets:
                                        acked.add(packet.seq)
                                        self.state.increment(packets_acked=1)
                                        self.state.set_progress_from_acks()
                                        self.state.event("ACK", packet.seq, "Sender received ACK", "success")
                                    while base in acked:
                                        packet_cache.pop(base, None)
                                        base += 1
                            except (BlockingIOError, ConnectionResetError, OSError):
                                break
                            except Exception as exc:
                                self.state.event("ACK_ERROR", detail=str(exc), status="error")
                                break
                            r_check, _, _ = select.select([sock], [], [], 0)
                            if not r_check:
                                break

                    # Check for packet timeouts and retransmit unACKed packets
                    now = time.time()
                    for seq in range(base, next_seq):
                        if seq not in acked and now - sent_at.get(seq, 0) > self.timeout:
                            retries[seq] = retries.get(seq, 0) + 1
                            self.state.record_telemetry(
                                "sender", "TIMEOUT", "DATA", seq,
                                status="warn", retransmission=True,
                                detail="ACK timeout; retransmission scheduled",
                            )
                            if retries[seq] > 40:
                                raise TimeoutError(f"Packet {seq} reached maximum retransmission attempts")
                            raw_packet = get_packet(seq)
                            self._send_data(sock, receiver_addr, seq, raw_packet, retransmit=True)
                            sent_at[seq] = now

                receiver_hash = self._finish(sock, receiver_addr, total_packets)
                output_path = self.receiver.output_path if self.receiver else f"udp://{self.receiver_ip}:{self.receiver_port}/{self.file_path.name}"
                self.state.finish(receiver_hash, output_path)

        except Exception as exc:
            self.state.set_receiver_status("Connection Failed")
            self.state.fail(f"Sender error: {exc}")
        finally:
            if file_handle:
                try:
                    file_handle.close()
                except Exception:
                    pass
            if self.receiver:
                self.receiver.stop_event.set()
                self.receiver.join(timeout=2.5)

    def _handshake(self, sock, receiver_addr, file_size, total_packets, sender_hash):
        self.state.set_receiver_status("Waiting for Receiver")
        metadata = {
            "session_id": self.session_id,
            "filename": self.file_path.name,
            "file_size": file_size,
            "total_packets": total_packets,
            "sha256": sender_hash,
            "payload_size": PAYLOAD_SIZE,
        }
        start_packet = make_packet(0, START, encode_metadata(metadata))
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                sock.sendto(start_packet, receiver_addr)
                start = parse_packet(start_packet)
                self.state.record_telemetry(
                    "sender", "START_SENT", "START", start.seq, start.length,
                    start.crc32, start.valid_crc,
                    detail=f"Metadata sent to {receiver_addr[0]}:{receiver_addr[1]}",
                )
            except OSError as exc:
                self.state.record_telemetry(
                    "sender", "SEND_FAILED", "START", 0, len(start_packet) - HEADER_SIZE,
                    status="error", detail=str(exc),
                )
                raise
            self.state.event("START", detail=f"Metadata sent for session {self.session_id} to {receiver_addr[0]}:{receiver_addr[1]}")
            ready, _, _ = select.select([sock], [], [], 0.3)
            if ready:
                try:
                    raw, _ = sock.recvfrom(4096)
                    packet = parse_packet(raw)
                    self.state.record_telemetry(
                        "sender", "READY_RECEIVED", packet.type_name,
                        packet.seq, packet.length, packet.crc32,
                        packet.valid_crc, "success" if packet.valid_crc else "error",
                        detail="Receiver handshake response",
                    )
                    if packet.valid_crc and packet.type == READY:
                        self.state.set_receiver_status("Receiver Ready")
                        self.state.event("HANDSHAKE", detail=f"START / READY completed with {receiver_addr[0]}:{receiver_addr[1]}", status="success")
                        return
                except (ConnectionResetError, OSError):
                    continue
                except Exception:
                    continue
        self.state.set_receiver_status("Connection Failed")
        raise TimeoutError(
            f"Handshake timed out. Receiver at {receiver_addr[0]}:{receiver_addr[1]} "
            "did not respond. Verify that the receiver is running, the address is "
            "correct, and inbound UDP traffic is allowed on the receiver firewall."
        )

    def _send_data(self, sock, receiver_addr, seq, raw_packet, retransmit):
        if random.random() < (self.packet_loss / 100):
            self.state.increment(packets_lost=1)
            self.state.event("LOST", seq, "Simulated DATA drop before UDP send", "error")
            self.state.record_telemetry(
                "sender", "SIMULATED_LOSS", "DATA", seq,
                len(raw_packet) - HEADER_SIZE, status="error",
                retransmission=retransmit,
                detail="Packet dropped before UDP send",
            )
            return
        try:
            sock.sendto(raw_packet, receiver_addr)
        except OSError as exc:
            self.state.record_telemetry(
                "sender", "SEND_FAILED", "DATA", seq,
                len(raw_packet) - HEADER_SIZE, status="error",
                retransmission=retransmit, detail=str(exc),
            )
            raise
        packet = parse_packet(raw_packet)
        self.state.record_telemetry(
            "sender", "DATA_SENT", "DATA", seq,
            packet.length, packet.crc32, packet.valid_crc, "success",
            retransmission=retransmit,
            detail="Retransmitted DATA" if retransmit else "DATA sent",
        )
        if retransmit:
            self.state.increment(retransmissions=1, packets_sent=1)
            self.state.event("RETRANSMIT", seq, "Timeout expired; packet resent", "warn")
        else:
            self.state.increment(packets_sent=1)
            self.state.event("DATA", seq, "DATA packet sent through UDP")

    def _finish(self, sock, receiver_addr, total_packets):
        fin = make_packet(total_packets, FIN)
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                sock.sendto(fin, receiver_addr)
                packet = parse_packet(fin)
                self.state.record_telemetry(
                    "sender", "FIN_SENT", "FIN", total_packets,
                    packet.length, packet.crc32, packet.valid_crc,
                    "success", detail="FIN sent",
                )
            except OSError as exc:
                self.state.record_telemetry(
                    "sender", "SEND_FAILED", "FIN", total_packets,
                    0, status="error", detail=str(exc),
                )
                raise
            self.state.event("FIN", detail="All DATA ACKed; FIN sent")
            ready, _, _ = select.select([sock], [], [], 0.4)
            if ready:
                try:
                    raw, _ = sock.recvfrom(4096)
                    packet = parse_packet(raw)
                    self.state.record_telemetry(
                        "sender", "FIN_ACK_RECEIVED", packet.type_name,
                        packet.seq, packet.length, packet.crc32,
                        packet.valid_crc, "success" if packet.valid_crc else "error",
                        detail="Receiver completion response",
                    )
                    if packet.valid_crc and packet.type == FIN_ACK:
                        receiver_hash = packet.payload.decode("ascii", errors="replace")
                        self.state.event("FIN_ACK", detail="Sender received FIN_ACK", status="success")
                        return receiver_hash
                except (ConnectionResetError, OSError):
                    continue
                except Exception:
                    continue
        raise TimeoutError("FIN/FIN_ACK close timed out")
