const $ = (id) => document.getElementById(id);

const fileInput = $("fileInput");
const startBtn = $("startBtn");
const resetBtn = $("resetBtn");
const message = $("formMessage");
const receiverIpInput = $("receiverIp");
const receiverPortInput = $("receiverPort");
const receiverStatusBadge = $("receiverStatusBadge");

let selectedPacketKey = null;
let pollTimer = null;

function validateIPv4(ip) {
  if (!ip) return false;
  const regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return regex.test(ip.trim());
}

function validatePort(port) {
  const n = Number(port);
  return !isNaN(n) && Number.isInteger(n) && n >= 1 && n <= 65535;
}

function formatBytes(bytes) {
  if (!bytes) return bytes === 0 ? "0 B" : "-";
  const units = ["B", "KB", "MB", "GB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function setFileMeta(file) {
  $("fileName").textContent = file ? file.name : "No file selected";
  $("fileSize").textContent = file ? formatBytes(file.size) : "-";
  $("fileType").textContent = file ? (file.type || "application/octet-stream") : "-";
}

fileInput.addEventListener("change", () => {
  setFileMeta(fileInput.files[0]);
  message.textContent = "";
});

startBtn.addEventListener("click", async () => {
  const file = fileInput.files[0];
  if (!file) {
    message.textContent = "Select a file before starting transfer.";
    return;
  }

  const receiverIp = (receiverIpInput ? receiverIpInput.value : "127.0.0.1").trim();
  const receiverPort = (receiverPortInput ? receiverPortInput.value : "9000").trim();

  if (!validateIPv4(receiverIp)) {
    message.textContent = `Validation Error: '${receiverIp}' is not a valid IPv4 address (e.g. 127.0.0.1 or 192.168.1.20).`;
    return;
  }

  if (!validatePort(receiverPort)) {
    message.textContent = `Validation Error: '${receiverPort}' is not a valid port. Must be between 1 and 65535.`;
    return;
  }

  const body = new FormData();
  body.append("file", file);
  body.append("receiver_ip", receiverIp);
  body.append("receiver_port", receiverPort);
  body.append("packet_loss", $("packetLoss").value);
  body.append("window_size", $("windowSize").value);
  body.append("timeout_ms", $("timeoutMs").value);
  startBtn.disabled = true;
  message.textContent = "";

  try {
    const response = await fetch("/api/transfer", { method: "POST", body });
    const data = await response.json();
    if (!response.ok) {
      message.textContent = data.error || "Unable to start transfer.";
      startBtn.disabled = false;
    } else {
      await refresh();
    }
  } catch (err) {
    message.textContent = "Network error connecting to backend API.";
    startBtn.disabled = false;
  }
});

resetBtn.addEventListener("click", async () => {
  try {
    const response = await fetch("/api/reset", { method: "POST" });
    const data = await response.json();
    if (!response.ok) {
      message.textContent = data.error || "Unable to reset dashboard.";
      return;
    }
    selectedPacketKey = null;
    message.textContent = "";
    await refresh();
  } catch (err) {
    message.textContent = "Failed to reset dashboard.";
  }
});

function renderEvents(events) {
  $("eventList").innerHTML = events.slice(0, 30).map((item) => `
    <div class="event ${item.status}">
      <strong>${item.time}</strong>
      <span>${item.event}${item.seq !== null && item.seq !== undefined ? ` #${item.seq}` : ""}</span>
      <span>${item.detail || ""}</span>
    </div>
  `).join("");
}

function renderPackets(packets) {
  if (!packets || packets.length === 0) {
    $("packetList").innerHTML = '<div style="padding: 10px; color: var(--muted);">No packets logged yet</div>';
    renderInspector(null);
    return;
  }

  const visiblePackets = packets.slice(0, 20);
  let activePacket = visiblePackets.find((p) => `${p.seq}-${p.type}` === selectedPacketKey);
  if (!activePacket) {
    activePacket = visiblePackets[0];
    selectedPacketKey = `${activePacket.seq}-${activePacket.type}`;
  }

  $("packetList").innerHTML = visiblePackets.map((packet) => {
    const key = `${packet.seq}-${packet.type}`;
    const isActive = key === selectedPacketKey ? "active" : "";
    return `
      <button class="packet-btn ${isActive}" data-key="${key}">
        <strong>#${packet.seq}</strong>
        <span>${packet.type}</span>
        <span>${packet.length} bytes</span>
      </button>
    `;
  }).join("");

  document.querySelectorAll(".packet-btn").forEach((button) => {
    button.addEventListener("click", () => {
      selectedPacketKey = button.dataset.key;
      const found = visiblePackets.find((p) => `${p.seq}-${p.type}` === selectedPacketKey);
      if (found) {
        document.querySelectorAll(".packet-btn").forEach((b) => b.classList.remove("active"));
        button.classList.add("active");
        renderInspector(found);
      }
    });
  });

  renderInspector(activePacket);
}

function renderInspector(packet) {
  const values = packet
    ? [packet.seq, packet.type, `${packet.length} bytes`, packet.crc32, packet.crc_valid ? "VALID" : "INVALID"]
    : ["-", "-", "-", "-", "-"];
  $("inspector").querySelectorAll("strong").forEach((node, index) => {
    node.textContent = values[index];
  });
}

function renderHistory(history) {
  $("historyBody").innerHTML = history.map((item) => `
    <tr>
      <td>${item.filename}</td>
      <td><code>${item.receiver_ip || "127.0.0.1"}:${item.receiver_port || 9000}</code></td>
      <td>${formatBytes(item.size)}</td>
      <td>${item.duration}s</td>
      <td>${item.throughput_mbps} Mbps</td>
      <td>${item.packets}</td>
      <td>${item.retransmissions}</td>
      <td>${item.packet_loss}%</td>
      <td>${item.integrity}</td>
      <td>${item.timestamp}</td>
    </tr>
  `).join("");
}

function updateDashboard(payload) {
  const state = payload.state;
  $("connectionState").textContent = state.status;
  $("progressText").textContent = `${state.progress || 0}%`;
  $("progressBar").style.width = `${state.progress || 0}%`;
  $("packetCount").textContent = `${state.packets_acked || 0} / ${state.total_packets || 0}`;
  $("ackCount").textContent = state.packets_acked || 0;
  $("retransCount").textContent = state.retransmissions || 0;
  $("dropCount").textContent = state.packets_lost || 0;
  $("windowStat").textContent = state.window_size || $("windowSize").value;
  $("throughput").textContent = `${state.throughput_mbps || 0} Mbps`;
  $("lossBadge").textContent = `Loss simulation: ${state.packet_loss ?? $("packetLoss").value}%`;
  $("senderHash").textContent = state.sender_hash || "-";
  $("receiverHash").textContent = state.receiver_hash || "-";

  // Receiver Connection Status Badge
  const receiverStatus = state.receiver_status || "Not Connected";
  if (receiverStatusBadge) {
    receiverStatusBadge.textContent = receiverStatus;
    const statusMap = {
      "Not Connected": "not-connected",
      "Waiting for Receiver": "waiting-for-receiver",
      "Receiver Ready": "receiver-ready",
      "Transfer in Progress": "transfer-in-progress",
      "Transfer Completed": "transfer-completed",
      "Connection Failed": "connection-failed"
    };
    receiverStatusBadge.className = `status-badge ${statusMap[receiverStatus] || "not-connected"}`;
  }

  const isTransferring = (state.status === "starting" || state.status === "transferring");
  const packetMarker = $("packetMarker");
  const ackMarker = $("ackMarker");
  if (packetMarker && ackMarker) {
    if (isTransferring) {
      packetMarker.classList.add("active");
      ackMarker.classList.add("active");
    } else {
      packetMarker.classList.remove("active");
      ackMarker.classList.remove("active");
    }
  }

  const integrity = $("integrityState");
  integrity.textContent = state.integrity_status === "VERIFIED" ? "HASH MATCH - FILE VERIFIED" : state.integrity_status;
  integrity.className = `verify ${String(state.integrity_status || "pending").toLowerCase()}`;

  if (state.filename) {
    $("fileName").textContent = state.filename;
    $("fileSize").textContent = formatBytes(state.file_size);
    $("fileType").textContent = state.file_type || "application/octet-stream";
  }

  renderEvents(payload.events || []);
  renderPackets(payload.packets || []);

  if (!isTransferring) {
    startBtn.disabled = false;
  }
}

async function refresh() {
  try {
    const statusResponse = await fetch("/api/status");
    if (statusResponse.ok) {
      updateDashboard(await statusResponse.json());
    }
    const historyResponse = await fetch("/api/history");
    if (historyResponse.ok) {
      renderHistory((await historyResponse.json()).history || []);
    }
  } catch (err) {
    // Graceful background poll retry
  }
}

pollTimer = setInterval(refresh, 500);
refresh();
