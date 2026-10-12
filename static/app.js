const $ = (id) => document.getElementById(id);
const notice = (message) => { $("notice").textContent = message; };

async function requestJSON(url, options = {}) {
  const response = await fetch(url, {
    headers: {"Content-Type": "application/json"},
    ...options
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.message || data.error || "Request failed");
  return data;
}

function safeText(value) {
  return String(value ?? "—").replace(/[&<>"']/g, ch => ({
    "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;"
  })[ch]);
}

async function refresh() {
  try {
    const [status, stats, events] = await Promise.all([
      requestJSON("/api/status"), requestJSON("/api/stats"), requestJSON("/api/events?limit=100")
    ]);
    const pill = $("statusPill");
    pill.className = "pill " + (status.running ? "online" : "offline");
    pill.textContent = status.running ? "● Monitoring" : "● Offline";
    $("totalEvents").textContent = stats.total_events;
    $("highEvents").textContent = stats.high;
    $("mediumEvents").textContent = stats.medium;
    $("uniqueSources").textContent = stats.unique_sources;

    if (status.error) notice("Monitor message: " + status.error + " — check permissions and capture-driver setup.");
    const body = $("eventsBody");
    if (!events.length) {
      body.innerHTML = '<tr><td colspan="7" class="empty">No events yet. Add demo events or start monitoring.</td></tr>';
    } else {
      body.innerHTML = events.map(e => `<tr>
        <td>${safeText(e.timestamp)}</td>
        <td>${safeText(e.src_ip)}</td><td>${safeText(e.dst_ip)}</td>
        <td>${safeText(e.protocol)}</td><td>${safeText(e.dst_port ?? "—")}</td>
        <td><span class="severity sev-${safeText(e.severity)}">${safeText(e.severity)}</span></td>
        <td>${e.source === "DEMO" ? '<span class="source-DEMO">DEMO · </span>' : ''}${safeText(e.message)}</td>
      </tr>`).join("");
    }
  } catch (error) {
    notice("Could not refresh dashboard: " + error.message);
  }
}

$("startBtn").addEventListener("click", async () => {
  try {
    const result = await requestJSON("/api/start", {
      method: "POST",
      body: JSON.stringify({interface: $("interfaceInput").value})
    });
    notice(result.message);
    await refresh();
  } catch (error) { notice("Could not start capture: " + error.message); }
});
$("stopBtn").addEventListener("click", async () => {
  try {
    const result = await requestJSON("/api/stop", {method:"POST", body:"{}"});
    notice(result.message);
    await refresh();
  } catch (error) { notice("Could not stop monitor: " + error.message); }
});
$("demoBtn").addEventListener("click", async () => {
  try {
    const result = await requestJSON("/api/demo", {method:"POST", body:"{}"});
    notice(result.message);
    await refresh();
  } catch (error) { notice(error.message); }
});
$("clearBtn").addEventListener("click", async () => {
  if (!confirm("Clear all saved event logs?")) return;
  try {
    await requestJSON("/api/clear", {method:"POST", body:"{}"});
    notice("Event log cleared.");
    await refresh();
  } catch (error) { notice(error.message); }
});
refresh();
setInterval(refresh, 3000);
