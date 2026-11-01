import json
import threading
import time
from collections import deque
from pathlib import Path
from typing import Optional

from config import HISTORY_FILE, MAX_RECENT_EVENTS


class TransferState:
    def __init__(self):
        self.lock = threading.RLock()
        self.current = self._empty()
        self.events = deque(maxlen=MAX_RECENT_EVENTS)
        self.packet_log = deque(maxlen=MAX_RECENT_EVENTS)
        self.history = self._load_history()
        self.error = None

    def _empty(self):
        return {
            "status": "ready",
            "message": "Ready for UDP transfer",
            "filename": None,
            "file_size": 0,
            "file_type": "",
            "total_packets": 0,
            "packets_sent": 0,
            "packets_acked": 0,
            "packets_received": 0,
            "duplicates": 0,
            "out_of_order": 0,
            "crc_errors": 0,
            "malformed_packets": 0,
            "packets_lost": 0,
            "retransmissions": 0,
            "progress": 0,
            "throughput_mbps": 0,
            "window_size": 8,
            "timeout_ms": 250,
            "packet_loss": 0,
            "sender_hash": "",
            "receiver_hash": "",
            "integrity_status": "PENDING",
            "start_time": None,
            "end_time": None,
            "duration_sec": 0,
            "udp_port": 9000,
            "receiver_ip": "127.0.0.1",
            "receiver_port": 9000,
            "receiver_status": "Not Connected",
        }

    def _load_history(self):
        if not Path(HISTORY_FILE).exists():
            return []
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as file:
                data = json.load(file)
            return data if isinstance(data, list) else []
        except (OSError, json.JSONDecodeError):
            return []

    def save_history(self):
        with open(HISTORY_FILE, "w", encoding="utf-8") as file:
            json.dump(self.history[-50:], file, indent=2)

    def reset(self):
        with self.lock:
            self.current = self._empty()
            self.events.clear()
            self.packet_log.clear()
            self.error = None

    def begin(self, filename, file_size, file_type, total_packets, window_size, timeout_ms, packet_loss, sender_hash, udp_port=9000, receiver_ip="127.0.0.1", receiver_port=9000):
        with self.lock:
            self.current = self._empty()
            self.current.update(
                {
                    "status": "starting",
                    "message": f"Initiating handshake with receiver at {receiver_ip}:{receiver_port}",
                    "filename": filename,
                    "file_size": file_size,
                    "file_type": file_type,
                    "total_packets": total_packets,
                    "window_size": window_size,
                    "timeout_ms": timeout_ms,
                    "packet_loss": packet_loss,
                    "sender_hash": sender_hash,
                    "start_time": time.time(),
                    "udp_port": receiver_port,
                    "receiver_ip": receiver_ip,
                    "receiver_port": receiver_port,
                    "receiver_status": "Waiting for Receiver",
                }
            )
            self.events.clear()
            self.packet_log.clear()
            self.error = None

    def set_receiver_status(self, status: str):
        with self.lock:
            self.current["receiver_status"] = status

    def update(self, **values):
        with self.lock:
            self.current.update(values)

    def increment(self, **values):
        with self.lock:
            for key, amount in values.items():
                self.current[key] = self.current.get(key, 0) + amount

    def set_progress_from_acks(self):
        with self.lock:
            total = max(1, self.current["total_packets"])
            self.current["progress"] = round((self.current["packets_acked"] / total) * 100, 1)
            start = self.current.get("start_time")
            if start:
                elapsed = max(0.001, time.time() - start)
                file_size = self.current.get("file_size", 0)
                transferred_bytes = min(self.current["packets_acked"] * 1024, file_size) if file_size > 0 else (self.current["packets_acked"] * 1024)
                bits = transferred_bytes * 8
                self.current["throughput_mbps"] = round(bits / elapsed / 1_000_000, 3)

    def event(self, event_type, seq=None, detail="", status="info"):
        with self.lock:
            item = {
                "id": int(time.time() * 1000_000),
                "time": time.strftime("%H:%M:%S"),
                "event": event_type,
                "seq": seq,
                "detail": detail,
                "status": status,
            }
            self.events.appendleft(item)
            return item

    def packet(self, packet):
        with self.lock:
            self.packet_log.appendleft(packet)

    def finish(self, receiver_hash, output_path):
        with self.lock:
            end = time.time()
            self.current["end_time"] = end
            start = self.current.get("start_time") or end
            self.current["duration_sec"] = round(end - start, 3)
            self.current["receiver_hash"] = receiver_hash
            self.current["integrity_status"] = "VERIFIED" if receiver_hash == self.current["sender_hash"] else "FAILED"
            self.current["status"] = "complete" if self.current["integrity_status"] == "VERIFIED" else "failed"
            self.current["receiver_status"] = "Transfer Completed" if self.current["status"] == "complete" else "Connection Failed"
            self.current["message"] = "Transfer complete and file verified" if self.current["status"] == "complete" else "Transfer complete but hashes differ"
            self.current["progress"] = 100 if self.current["status"] == "complete" else self.current["progress"]
            history_item = {
                "filename": self.current["filename"],
                "size": self.current["file_size"],
                "duration": self.current["duration_sec"],
                "throughput_mbps": self.current["throughput_mbps"],
                "packets": self.current["total_packets"],
                "retransmissions": self.current["retransmissions"],
                "packet_loss": self.current["packet_loss"],
                "integrity": self.current["integrity_status"],
                "receiver_ip": self.current.get("receiver_ip", "127.0.0.1"),
                "receiver_port": self.current.get("receiver_port", 9000),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "output_path": str(output_path),
            }
            self.history.append(history_item)
            self.history = self.history[-50:]
            self.save_history()

    def fail(self, message):
        with self.lock:
            self.current["status"] = "failed"
            self.current["message"] = message
            self.current["receiver_status"] = "Connection Failed"
            self.error = message
            self.event("ERROR", detail=message, status="error")

    def snapshot(self):
        with self.lock:
            return {
                "state": dict(self.current),
                "events": list(self.events),
                "packets": list(self.packet_log),
            }

    def history_snapshot(self):
        with self.lock:
            return list(reversed(self.history))


STATE = TransferState()
