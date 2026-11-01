const $ = (id) => document.getElementById(id);

const fileInput = $("fileInput");
const dropZone = $("dropZone");
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
  if (bytes === 0) return "0 B";
  if (!bytes) return "-";
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
  
  const payloadStep = document.querySelector(".pipe-step");
  if (payloadStep) {
    if (file) {
      payloadStep.classList.add("active");
    } else {
      payloadStep.classList.remove("active");
    }
  }
}

// File Input Listeners (Click & Native selection)
if (fileInput) {
  fileInput.addEventListener("change", () => {
    setFileMeta(fileInput.files[0]);
    if (message) message.textContent = "";
  });
}

// Drag & Drop Implementation
if (dropZone && fileInput) {
  ["dragenter", "dragover"].forEach((eventName) => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.add("dragover");
    });
  });

  ["dragleave", "drop"].forEach((eventName) => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.remove("dragover");
    });
  });

  dropZone.addEventListener("drop", (e) => {
    const dt = e.dataTransfer;
    if (dt && dt.files && dt.files.length > 0) {
      fileInput.files = dt.files;
      setFileMeta(dt.files[0]);
      if (message) message.textContent = "";
    }
  });
}

// Transfer Start Action
if (startBtn) {
  startBtn.addEventListener("click", async () => {
    const file = fileInput ? fileInput.files[0] : null;
    if (!file) {
      if (message) message.textContent = "Select a payload file before starting UDP transfer.";
      return;
    }

    const receiverIp = (receiverIpInput ? receiverIpInput.value : "127.0.0.1").trim();
    const receiverPort = (receiverPortInput ? receiverPortInput.value : "9000").trim();

    if (!validateIPv4(receiverIp)) {
      if (message) message.textContent = `Validation Error: '${receiverIp}' is not a valid IPv4 address (e.g. 127.0.0.1 or 192.168.1.20).`;
      return;
    }

    if (!validatePort(receiverPort)) {
      if (message) message.textContent = `Validation Error: '${receiverPort}' is not a valid port. Must be between 1 and 65535.`;
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
    if (message) message.textContent = "";

    try {
      const response = await fetch("/api/transfer", { method: "POST", body });
      const data = await response.json();
      if (!response.ok) {
        if (message) message.textContent = data.error || "Unable to initiate transfer session.";
        startBtn.disabled = false;
      } else {
        await refresh();
      }
    } catch (err) {
      if (message) message.textContent = "Network error connecting to backend API.";
      startBtn.disabled = false;
    }
  });
}

// Reset Dashboard Action with Confirmation
if (resetBtn) {
  resetBtn.addEventListener("click", async () => {
    if (!confirm("Are you sure you want to reset the transfer session and dashboard?")) {
      return;
    }

    try {
      const response = await fetch("/api/reset", { method: "POST" });
      const data = await response.json();
      if (!response.ok) {
        if (message) message.textContent = data.error || "Unable to reset dashboard.";
        return;
      }
      selectedPacketKey = null;
      if (message) message.textContent = "";
      await refresh();
    } catch (err) {
      if (message) message.textContent = "Failed to communicate with reset API.";
    }
  });
}

// Clipboard Copy Helpers
document.querySelectorAll(".btn-copy").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const targetId = btn.getAttribute("data-target");
    const targetEl = $(targetId);
    if (!targetEl) return;
    const text = targetEl.textContent.trim();
    if (!text || text === "-") return;
    try {
      await navigator.clipboard.writeText(text);
      btn.textContent = "COPIED";
      btn.classList.add("copied");
      setTimeout(() => {
        btn.textContent = "COPY";
        btn.classList.remove("copied");
      }, 1500);
    } catch (err) {
      console.warn("Clipboard write failed:", err);
    }
  });
});

function renderEvents(events) {
  const container = $("eventList");
  if (!container) return;
  if (!events || events.length === 0) {
    container.innerHTML = '<div class="empty-state mono">No network activity recorded</div>';
    return;
  }

  container.innerHTML = events.slice(0, 40).map((item) => {
    const statusClass = item.status || "info";
    const seqStr = (item.seq !== null && item.seq !== undefined) ? ` #${item.seq}` : "";
    return `
      <div class="event-row ${statusClass}">
        <span class="event-time mono">${item.time}</span>
        <span class="event-tag mono">${item.event}${seqStr}</span>
        <span class="event-detail" title="${item.detail || ""}">${item.detail || "-"}</span>
      </div>
    `;
  }).join("");
}

function renderPackets(packets) {
  const listEl = $("packetList");
  if (!listEl) return;
  if (!packets || packets.length === 0) {
    listEl.innerHTML = '<div class="empty-state mono">No packets in buffer</div>';
    renderInspector(null);
    return;
  }

  const visiblePackets = packets.slice(0, 24);
  let activePacket = visiblePackets.find((p) => `${p.seq}-${p.type}` === selectedPacketKey);
  if (!activePacket) {
    activePacket = visiblePackets[0];
    selectedPacketKey = `${activePacket.seq}-${activePacket.type}`;
  }

  listEl.innerHTML = visiblePackets.map((packet) => {
    const key = `${packet.seq}-${packet.type}`;
    const isActive = key === selectedPacketKey ? "active" : "";
    return `
      <button type="button" class="packet-pill ${isActive}" data-key="${key}">
        #${packet.seq} ${packet.type}
      </button>
    `;
  }).join("");

  listEl.querySelectorAll(".packet-pill").forEach((button) => {
    button.addEventListener("click", () => {
      selectedPacketKey = button.dataset.key;
      const found = visiblePackets.find((p) => `${p.seq}-${p.type}` === selectedPacketKey);
      if (found) {
        listEl.querySelectorAll(".packet-pill").forEach((b) => b.classList.remove("active"));
        button.classList.add("active");
        renderInspector(found);
      }
    });
  });

  renderInspector(activePacket);
}

function renderInspector(packet) {
  const inspector = $("inspector");
  if (!inspector) return;
  
  const values = packet
    ? [
        `SEQ #${packet.seq}`,
        packet.type,
        `${packet.length} bytes`,
        `0x${packet.crc32}`,
        packet.crc_valid ? "VALID (MATCH)" : "CORRUPT (MISMATCH)"
      ]
    : ["-", "-", "-", "-", "-"];

  const strongNodes = inspector.querySelectorAll("strong");
  strongNodes.forEach((node, index) => {
    if (index < values.length) {
      node.textContent = values[index];
      if (index === 4 && packet) {
        node.style.color = packet.crc_valid ? "var(--color-success)" : "var(--color-error)";
      } else if (index === 4) {
        node.style.color = "";
      }
    }
  });
}

function renderHistory(history) {
  const body = $("historyBody");
  if (!body) return;
  if (!history || history.length === 0) {
    body.innerHTML = `<tr><td colspan="10" class="empty-state mono">No transfer history recorded</td></tr>`;
    return;
  }

  body.innerHTML = history.map((item) => {
    const isVerified = item.integrity === "VERIFIED";
    const badgeClass = isVerified ? "verified" : "failed";
    const endpoint = `${item.receiver_ip || "127.0.0.1"}:${item.receiver_port || 9000}`;
    return `
      <tr>
        <td style="font-weight: 700;">${item.filename}</td>
        <td><code class="mono">${endpoint}</code></td>
        <td class="mono">${formatBytes(item.size)}</td>
        <td class="mono">${item.duration}s</td>
        <td class="mono">${item.throughput_mbps} Mbps</td>
        <td class="mono">${item.packets}</td>
        <td class="mono">${item.retransmissions}</td>
        <td class="mono">${item.packet_loss}%</td>
        <td><span class="table-badge ${badgeClass}">${item.integrity}</span></td>
        <td class="mono" style="color: var(--text-secondary);">${item.timestamp}</td>
      </tr>
    `;
  }).join("");
}

function updatePipeline(state, hasFile) {
  const steps = document.querySelectorAll(".pipe-step");
  if (!steps || steps.length === 0) return;

  steps.forEach((s) => s.classList.remove("active"));
  if (hasFile) steps[0]?.classList.add("active");

  const isTransferring = (state.status === "starting" || state.status === "transferring");
  const isComplete = (state.status === "complete");

  if (isTransferring) {
    steps[0]?.classList.add("active");
    steps[1]?.classList.add("active");
    steps[2]?.classList.add("active");
    steps[3]?.classList.add("active");
    steps[4]?.classList.add("active");
  } else if (isComplete) {
    steps.forEach((s) => s.classList.add("active"));
  }
}

function updateDashboard(payload) {
  const state = payload.state;
  const isTransferring = (state.status === "starting" || state.status === "transferring");
  const isFailed = (state.status === "failed");
  const isComplete = (state.status === "complete");

  if ($("connectionState")) $("connectionState").textContent = state.status;
  
  // LED Status Indicator
  const led = $("statusLed");
  if (led) {
    led.className = "status-indicator" + (isTransferring ? " transferring" : (isFailed ? " failed" : ""));
  }

  if ($("progressText")) $("progressText").textContent = `${state.progress || 0}%`;
  if ($("progressBar")) $("progressBar").style.width = `${state.progress || 0}%`;
  if ($("packetCount")) $("packetCount").textContent = `${state.packets_acked || 0} / ${state.total_packets || 0}`;
  if ($("ackCount")) $("ackCount").textContent = state.packets_acked || 0;
  if ($("retransCount")) $("retransCount").textContent = state.retransmissions || 0;
  if ($("dropCount")) $("dropCount").textContent = state.packets_lost || 0;
  if ($("windowStat")) $("windowStat").textContent = state.window_size || ($("windowSize") ? $("windowSize").value : 8);
  if ($("throughput")) $("throughput").textContent = `${state.throughput_mbps || 0} Mbps`;
  if ($("lossBadge")) $("lossBadge").textContent = `Loss simulation: ${state.packet_loss ?? ($("packetLoss") ? $("packetLoss").value : 10)}%`;
  
  if ($("senderHash")) $("senderHash").textContent = state.sender_hash || "-";
  if ($("receiverHash")) $("receiverHash").textContent = state.receiver_hash || "-";

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

  // Animated Flow Packet Signals
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

  // File Integrity State Badge
  const integrity = $("integrityState");
  if (integrity) {
    let text = state.integrity_status;
    let className = "verify pending";
    if (state.integrity_status === "VERIFIED") {
      text = "HASH MATCH \u2014 FILE INTEGRITY CONFIRMED";
      className = "verify verified";
    } else if (state.integrity_status === "FAILED") {
      text = "HASH MISMATCH \u2014 INTEGRITY FAILED";
      className = "verify failed";
    } else if (isTransferring) {
      text = "VERIFYING INGESTION STREAM...";
      className = "verify pending";
    } else {
      text = "PENDING \u2014 AWAITING TRANSFER";
      className = "verify pending";
    }
    integrity.textContent = text;
    integrity.className = className;
  }

  // Update Metadata If Available From Backend
  const hasFile = Boolean(state.filename || (fileInput && fileInput.files && fileInput.files[0]));
  if (state.filename) {
    if ($("fileName")) $("fileName").textContent = state.filename;
    if ($("fileSize")) $("fileSize").textContent = formatBytes(state.file_size);
    if ($("fileType")) $("fileType").textContent = state.file_type || "application/octet-stream";
  }

  updatePipeline(state, hasFile);
  renderEvents(payload.events || []);
  renderPackets(payload.packets || []);

  // Form Controls Availability
  if (startBtn) {
    startBtn.disabled = isTransferring;
  }
  if (receiverIpInput) receiverIpInput.disabled = isTransferring;
  if (receiverPortInput) receiverPortInput.disabled = isTransferring;
  if ($("packetLoss")) $("packetLoss").disabled = isTransferring;
  if ($("windowSize")) $("windowSize").disabled = isTransferring;
  if ($("timeoutMs")) $("timeoutMs").disabled = isTransferring;
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
    // Graceful background retry without flooding
  }
}

pollTimer = setInterval(refresh, 500);
refresh();
