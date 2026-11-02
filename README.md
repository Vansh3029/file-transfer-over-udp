# Reliable File Transfer over UDP

A complete BTech/Data Communication project that demonstrates how reliable file transfer can be implemented at the application layer over UDP.

The web dashboard controls a real Python UDP sender and UDP receiver. It does not fake packet counts, ACKs, retransmissions, throughput, progress, CRC32, SHA-256, or packet loss. The only artificial behavior is the configurable DATA packet loss simulator used to demonstrate timeout and retransmission.

## Features

- UDP socket communication with configurable IP address and port (default: `127.0.0.1:9000` or `0.0.0.0:9000` for LAN)
- Full LAN (Local Area Network) file transfer support between separate machines
- Receiver Connection Status Indicator (`Not Connected`, `Waiting for Receiver`, `Receiver Ready`, `Transfer in Progress`, `Transfer Completed`, `Connection Failed`)
- Exact packet header: `struct.Struct("!IBHI")` (11 bytes)
- Packet types: `START`, `READY`, `DATA`, `ACK`, `FIN`, `FIN_ACK`
- 1024-byte binary file chunking
- CRC32 validation protecting header fields and payload
- START/READY handshake with session isolation
- Sliding window with configurable size (1, 4, 8, 16, 32, 64)
- Per-packet ACKs, timeout, and Selective Repeat retransmission
- Duplicate packet handling and out-of-order packet reassembly
- SHA-256 verification of original and received file
- Configurable packet-loss simulation (0% to 50%)
- Live progress, throughput, packet, ACK, drop, and retransmission statistics
- Packet flow visualization and interactive packet inspector
- Transfer history stored in `transfer_history.json`
- Windows-friendly `run.bat` launcher

## Architecture

```text
UDP File Transfer
|
|-- frontend/
|   |-- index.html
|   |-- style.css
|   `-- app.js
|
|-- backend/
|   |-- app.py          HTTP API and static file server
|   |-- protocol.py     UDP packet format, CRC32, parse/make functions
|   |-- udp_sender.py   sliding-window sender, timeout, retransmission
|   |-- udp_receiver.py receiver, ACKs, duplicate/out-of-order handling
|   |-- integrity.py    SHA-256 file hashing
|   |-- state.py        real-time transfer state and history
|   `-- config.py       ports, directories, defaults
|
|-- uploads/
|-- received_files/
|-- tests/
|-- run.bat
`-- requirements.txt
```

## Packet Format

The project implements this header exactly:

```python
HEADER = struct.Struct("!IBHI")
```

```text
Sequence Number : 4 bytes
Type            : 1 byte
Length          : 2 bytes
CRC32           : 4 bytes
Payload         : up to 1024 bytes
```

CRC32 is calculated over the payload bytes.

## How UDP Works Here

UDP sends independent datagrams. It does not guarantee delivery, order, duplicate prevention, or retransmission. This project adds those features in the application layer:

1. Sender sends `START` metadata.
2. Receiver replies `READY`.
3. Sender chunks the file into 1024-byte `DATA` packets.
4. Receiver validates CRC32 and ACKs every valid DATA sequence.
5. Sender retransmits unacknowledged packets after timeout.
6. Receiver stores chunks by sequence number and ignores duplicate writes.
7. Sender sends `FIN`.
8. Receiver reassembles the file and sends `FIN_ACK` with SHA-256.
9. Dashboard compares sender and receiver hashes.

## Why UDP Instead of TCP

UDP has low overhead and exposes datagram behavior directly. That makes it useful for demonstrating reliability concepts normally hidden inside TCP, including ACKs, sequence numbers, sliding windows, checksums, timeouts, retransmissions, reordering, and duplicate handling.

## Key Concepts

ACK: Lets the sender know exactly which sequence number arrived successfully.

CRC32: Detects corruption at packet level. Corrupted packets are rejected and not ACKed.

SHA-256: Verifies that the final reconstructed file matches the original complete file.

Sliding Window: Allows multiple packets to be in flight instead of waiting after every packet. The sender tracks `base`, `next_sequence_number`, acknowledged packets, and in-flight timestamps.

Timeout and Retransmission: If no ACK is received before the configured timeout, the sender resends that DATA packet.

Out-of-Order Handling: The receiver stores packets in a dictionary by sequence number and writes them in order only after all chunks arrive.

## Installation

Python 3 is required. No external packages are needed.

```bat
cd "C:\Users\VANSH\Desktop\file transfer over udp"
python --version
```

## Running

Option 1:

```bat
run.bat
```

Option 2:

```bat
python backend\app.py
```

Open:

```text
http://127.0.0.1:8000
```

## LAN or Mobile Hotspot File Transfer Setup

To transfer files between two machines on the same Wi-Fi network or mobile
hotspot:

### 1. Receiver Machine (e.g. `192.168.1.20`)
1. Find the receiver's address on the network it is currently using. On Windows,
   run `ipconfig` and use the IPv4 address shown for the active Wi-Fi or
   hotspot adapter. Do not use `127.0.0.1`; that address means "this same
   computer".
2. On Windows PowerShell as Administrator, allow inbound traffic on UDP port
   9000 for all network profiles, including mobile hotspots:
   ```powershell
   New-NetFirewallRule -DisplayName "UDP File Transfer Receiver (Port 9000)" -Direction Inbound -Protocol UDP -LocalPort 9000 -Action Allow -Profile Any
   ```
3. Start the receiver:
   - **Option A (Web Dashboard + Receiver):** Run `run.bat` or `python backend\app.py`.
   - **Option B (Standalone Receiver):** Run `python backend\udp_receiver.py --host 0.0.0.0 --port 9000`.

### 2. Sender Machine (e.g. `192.168.1.10`)
1. Open the sender dashboard: `http://127.0.0.1:8000`.
2. In **Receiver Configuration**:
   - Set **Receiver IP Address** to the Receiver PC's LAN IP: `192.168.1.20`.
   - Set **Receiver UDP Port** to: `9000`.
3. Choose a file and click **START UDP TRANSFER**.
4. The dashboard will transition:
   `Not Connected` -> `Waiting for Receiver` -> `Receiver Ready` -> `Transfer in Progress` -> `Transfer Completed`.
5. The received file is saved in `received_files/` on the Receiver machine and verified via SHA-256.

### Hotspot troubleshooting

- The Windows laptop must be the **receiver** when sending from the Mac, and
  its Windows Firewall must allow inbound UDP 9000. Hotspot connections are
  commonly classified as `Public`, even when ordinary Wi-Fi is classified as
  `Private`.
- Confirm both machines are connected to the same hotspot and use the
  receiver's current hotspot IPv4 address. Hotspot addresses can change after
  reconnecting.
- If the receiver still times out, temporarily test with the Windows Firewall
  disabled only to confirm the cause, then re-enable it and add the rule above.
- The receiver binds to `0.0.0.0:9000`, so no code or configuration change is
  needed to make it listen on the hotspot interface.

## Demo Scenario

1. Start the app.
2. Open the dashboard.
3. Choose a PDF, image, video, ZIP, or any binary file.
4. Set packet loss to `10%`.
5. Set sliding window to `8`.
6. Set timeout to `250 ms`.
7. Click `START UDP TRANSFER`.
8. Watch DATA, ACK, LOST, RETRANSMIT, FIN, and FIN_ACK events.
9. Confirm `HASH MATCH - FILE VERIFIED`.
10. Open the received file from `received_files/`.

## Testing

Run:

```bat
python -m unittest discover tests
```

Suggested manual tests:

```text
Loss = 0%, Window = 8  -> SHA-256 MATCH
Loss = 10%, Window = 8 -> retransmission recovery and SHA-256 MATCH
Loss = 20%, Window = 16 -> more retransmissions and SHA-256 MATCH
Window = 1, 4, 8, 16 -> compare throughput and retransmissions
TXT, PDF, JPG, MP4, ZIP -> all should reconstruct as binary files
```

## Wireshark

Use this display filter:

```text
udp.port == 9000
```

You will see the local UDP packets used by the project. The application-level header appears inside the UDP payload.

## Safety

- Filenames are sanitized before writing.
- Received files are restricted to `received_files/`.
- Uploaded files are stored in `uploads/`.
- Uploaded files are never executed.
- Packet payload lengths are validated.
- Malformed and corrupted packets are handled without crashing the app.

## Future Scope

- Add selective ACK ranges.
- Add adaptive timeout based on measured round-trip time.
- Add optional ACK-loss simulation.
- Add multiple concurrent transfer sessions.
- Add drag-and-drop file upload.
- Add downloadable CSV reports for experiments.
