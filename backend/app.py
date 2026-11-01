import ipaddress
import json
import threading
from dataclasses import dataclass
from http import HTTPStatus
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from config import (
    DEFAULT_PACKET_LOSS,
    DEFAULT_RECEIVER_IP,
    DEFAULT_RECEIVER_PORT,
    DEFAULT_TIMEOUT_MS,
    DEFAULT_WINDOW_SIZE,
    FRONTEND_DIR,
    HTTP_HOST,
    HTTP_PORT,
    MAX_UPLOAD_SIZE,
    RECEIVER_LISTEN_HOST,
    RECEIVER_LISTEN_PORT,
    UPLOAD_DIR,
)
from state import STATE
from udp_receiver import UDPReceiver, sanitize_filename
from udp_sender import ReliableUDPSender


TRANSFER_THREAD = None
TRANSFER_LOCK = threading.RLock()
GLOBAL_RECEIVER = None


def ensure_global_receiver():
    global GLOBAL_RECEIVER
    with TRANSFER_LOCK:
        if GLOBAL_RECEIVER is None or not GLOBAL_RECEIVER.is_alive():
            try:
                GLOBAL_RECEIVER = UDPReceiver(STATE, host=RECEIVER_LISTEN_HOST, port=RECEIVER_LISTEN_PORT)
                GLOBAL_RECEIVER.start()
                GLOBAL_RECEIVER.ready_event.wait(timeout=2.0)
            except Exception as exc:
                print(f"Warning: Could not start default receiver on {RECEIVER_LISTEN_HOST}:{RECEIVER_LISTEN_PORT}: {exc}")


def validate_ipv4(ip_str: str) -> bool:
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return ip.version == 4
    except ValueError:
        return False


def validate_port(port_val) -> int:
    try:
        val = int(port_val)
        if 1 <= val <= 65535:
            return val
    except (TypeError, ValueError):
        pass
    return None


@dataclass
class UploadedFile:
    filename: str
    data: bytes


def json_bytes(data):
    return json.dumps(data).encode("utf-8")


def clamp_int(value, default, minimum, maximum):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, parsed))


def parse_content_disposition(value):
    result = {}
    for part in value.split(";"):
        part = part.strip()
        if "=" in part:
            key, raw = part.split("=", 1)
            result[key.lower()] = raw.strip().strip('"')
    return result


def parse_multipart(content_type, body):
    if not content_type or "multipart/form-data" not in content_type:
        raise ValueError("Expected multipart/form-data upload")
    boundary_marker = "boundary="
    if boundary_marker not in content_type:
        raise ValueError("Missing multipart boundary")
    boundary = content_type.split(boundary_marker, 1)[1].split(";", 1)[0].strip().strip('"')
    delimiter = ("--" + boundary).encode("utf-8")
    fields = {}
    files = {}

    for section in body.split(delimiter):
        section = section.strip(b"\r\n")
        if not section or section == b"--":
            continue
        if section.endswith(b"--"):
            section = section[:-2].rstrip(b"\r\n")
        if b"\r\n\r\n" not in section:
            continue
        raw_headers, data = section.split(b"\r\n\r\n", 1)
        headers = {}
        for line in raw_headers.decode("utf-8", errors="replace").split("\r\n"):
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.lower()] = value.strip()
        disposition = parse_content_disposition(headers.get("content-disposition", ""))
        name = disposition.get("name")
        if not name:
            continue
        if "filename" in disposition:
            files[name] = UploadedFile(disposition.get("filename", ""), data)
        else:
            fields[name] = data.decode("utf-8", errors="replace")
    return fields, files


class AppHandler(SimpleHTTPRequestHandler):
    server_version = "ReliableUDPHTTP/1.0"

    def log_message(self, format, *args):
        print("[%s] %s" % (self.log_date_time_string(), format % args))

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/status":
            return self.send_json(STATE.snapshot())
        if parsed.path == "/api/history":
            return self.send_json({"history": STATE.history_snapshot()})
        if parsed.path == "/api/packet":
            qs = parse_qs(parsed.query)
            index = clamp_int((qs.get("index") or ["0"])[0], 0, 0, 9999)
            packets = STATE.snapshot()["packets"]
            packet = packets[index] if index < len(packets) else None
            return self.send_json({"packet": packet})
        return self.serve_static(parsed.path)

    def do_POST(self):
        if self.path == "/api/transfer":
            return self.start_transfer()
        if self.path == "/api/reset":
            with TRANSFER_LOCK:
                if TRANSFER_THREAD and TRANSFER_THREAD.is_alive():
                    return self.send_json({"ok": False, "error": "Cannot reset dashboard while a transfer is in progress"}, HTTPStatus.CONFLICT)
                STATE.reset()
                return self.send_json({"ok": True})
        self.send_error(HTTPStatus.NOT_FOUND)

    def serve_static(self, request_path):
        if request_path in ("", "/"):
            request_path = "/index.html"
        target = (FRONTEND_DIR / request_path.lstrip("/")).resolve()
        frontend_root = FRONTEND_DIR.resolve()
        if not str(target).startswith(str(frontend_root)) or not target.exists() or target.is_dir():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        content_type = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
        }.get(target.suffix.lower(), "application/octet-stream")
        data = target.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, data, status=HTTPStatus.OK):
        body = json_bytes(data)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def start_transfer(self):
        global TRANSFER_THREAD
        with TRANSFER_LOCK:
            if TRANSFER_THREAD and TRANSFER_THREAD.is_alive():
                return self.send_json({"ok": False, "error": "A transfer is already running"}, HTTPStatus.CONFLICT)

            content_length = clamp_int(self.headers.get("Content-Length"), 0, 0, MAX_UPLOAD_SIZE + 10_000)
            if content_length <= 0:
                return self.send_json({"ok": False, "error": "No upload body received"}, HTTPStatus.BAD_REQUEST)
            if content_length > MAX_UPLOAD_SIZE + 10_000:
                return self.send_json({"ok": False, "error": "Upload is too large"}, HTTPStatus.BAD_REQUEST)

            body = self.rfile.read(content_length)
            try:
                fields, files = parse_multipart(self.headers.get("Content-Type"), body)
            except ValueError as exc:
                return self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            if "file" not in files or not files["file"].filename:
                return self.send_json({"ok": False, "error": "Select a file before starting transfer"}, HTTPStatus.BAD_REQUEST)

            upload = files["file"]
            filename = sanitize_filename(upload.filename)
            upload_path = (UPLOAD_DIR / filename).resolve()
            if not str(upload_path).startswith(str(UPLOAD_DIR.resolve())):
                upload_path = UPLOAD_DIR / "uploaded_file.bin"
            suffix = 1
            while upload_path.exists():
                upload_path = UPLOAD_DIR / f"{upload_path.stem}_{suffix}{upload_path.suffix}"
                suffix += 1
            upload_path.write_bytes(upload.data)

            window_size = clamp_int(fields.get("window_size"), DEFAULT_WINDOW_SIZE, 1, 64)
            timeout_ms = clamp_int(fields.get("timeout_ms"), DEFAULT_TIMEOUT_MS, 25, 5000)
            packet_loss = clamp_int(fields.get("packet_loss"), DEFAULT_PACKET_LOSS, 0, 90)

            receiver_ip = (fields.get("receiver_ip") or DEFAULT_RECEIVER_IP).strip()
            receiver_port_raw = fields.get("receiver_port") or DEFAULT_RECEIVER_PORT

            if not validate_ipv4(receiver_ip):
                return self.send_json({"ok": False, "error": f"Invalid IPv4 address: '{receiver_ip}'. Example valid addresses: 127.0.0.1 or 192.168.1.20"}, HTTPStatus.BAD_REQUEST)

            receiver_port = validate_port(receiver_port_raw)
            if receiver_port is None:
                return self.send_json({"ok": False, "error": f"Invalid UDP port: '{receiver_port_raw}'. Port must be between 1 and 65535."}, HTTPStatus.BAD_REQUEST)

            # If sending to local receiver address, ensure the global receiver is active
            if receiver_ip in ("127.0.0.1", "0.0.0.0", "localhost") and receiver_port == RECEIVER_LISTEN_PORT:
                ensure_global_receiver()

            sender = ReliableUDPSender(
                STATE,
                upload_path,
                window_size,
                timeout_ms,
                packet_loss,
                receiver_ip=receiver_ip,
                receiver_port=receiver_port,
            )
            TRANSFER_THREAD = threading.Thread(target=sender.run, daemon=True)
            TRANSFER_THREAD.start()
            return self.send_json({"ok": True, "message": "UDP transfer started"})


def main():
    print(f"Reliable File Transfer over UDP")
    print(f"Dashboard available at: http://127.0.0.1:{HTTP_PORT} (and http://<LAN-IP>:{HTTP_PORT})")
    print(f"Receiver listening on: {RECEIVER_LISTEN_HOST}:{RECEIVER_LISTEN_PORT}")
    print(f"Wireshark display filter: udp.port == {RECEIVER_LISTEN_PORT}")

    ensure_global_receiver()
    server = ThreadingHTTPServer((HTTP_HOST, HTTP_PORT), AppHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped")
    finally:
        server.server_close()
        if GLOBAL_RECEIVER:
            GLOBAL_RECEIVER.stop_event.set()
            GLOBAL_RECEIVER.join(timeout=2.0)


if __name__ == "__main__":
    main()
