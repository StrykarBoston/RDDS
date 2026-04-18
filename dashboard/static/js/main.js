/**
 * RDDS Dashboard — main.js
 * Real-time data polling, charts, and UI interactions.
 */

'use strict';

// ─────────────────────────────────────────────
//  STATE
// ─────────────────────────────────────────────
let allDevices = [];
let allAlerts = [];
let timelineChart = null;
let severityChart = null;
let pollInterval = null;

const POLL_MS = 5000;   // 5-second refresh

// ─────────────────────────────────────────────
//  INIT
// ─────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  initCharts();
  loadAll();
  startPolling();
});

function startPolling() {
  pollInterval = setInterval(loadAll, POLL_MS);
}

async function loadAll() {
  await Promise.allSettled([
    fetchDevices(),
    fetchAlerts(),
    fetchStats()
  ]);
  updateTimestamp();
  updateStatus(true);
}

function updateTimestamp() {
  const el = document.getElementById('last-updated');
  if (el) el.textContent = 'Last updated: ' + new Date().toLocaleTimeString();
}

function updateStatus(ok) {
  const dot = document.getElementById('status-dot');
  const text = document.getElementById('status-text');
  if (!dot || !text) return;
  if (ok) {
    dot.classList.remove('offline');
    text.textContent = 'Monitoring active';
  } else {
    dot.classList.add('offline');
    text.textContent = 'Connection lost';
  }
}

// ─────────────────────────────────────────────
//  FETCH DATA
// ─────────────────────────────────────────────

async function fetchDevices() {
  try {
    const res = await fetch('/api/devices');
    const data = await res.json();
    allDevices = data.devices || [];
    renderDevicesTable(allDevices);
    updateNavCount('nav-device-count', allDevices.length);
  } catch (e) { updateStatus(false); }
}

async function fetchAlerts() {
  try {
    const res = await fetch('/api/alerts?limit=200');
    const data = await res.json();
    allAlerts = data.alerts || [];
    renderOverviewAlerts(allAlerts.slice(0, 6));
    renderFullAlerts(allAlerts);
    updateNavCount('nav-alert-count', allAlerts.length);
  } catch (_) { }
}

async function fetchStats() {
  try {
    const res = await fetch('/api/stats');
    const data = await res.json();
    const s = data.stats || {};

    setText('stat-total-devices', s.total_devices || 0);
    setText('stat-rogue', s.rogue_devices || 0);
    setText('stat-alerts', s.total || 0);
    const trst = (s.total_devices || 0) - (s.rogue_devices || 0);
    setText('stat-whitelisted', Math.max(trst, 0));

    updateSeverityChart(s);
    updateTimelineChart(data.history || []);
  } catch (_) { }
}

// ─────────────────────────────────────────────
//  RENDER: DEVICES TABLE
// ─────────────────────────────────────────────

function renderDevicesTable(devices) {
  const tbody = document.getElementById('devices-tbody');
  if (!tbody) return;

  if (!devices.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No devices discovered yet. Run a scan.</td></tr>';
    return;
  }

  tbody.innerHTML = devices.map(d => {
    const score = d.risk_score || 0;
    const barColor = score >= 80 ? '#ff3b5c' :
      score >= 60 ? '#ff8c42' :
        score >= 40 ? '#fbbf24' : '#00ff88';
    const statusCls = d.is_whitelisted ? 'status-trusted'
      : score >= 60 ? 'status-rogue' : 'status-unknown';
    const statusTxt = d.is_whitelisted ? '✓ Trusted'
      : score >= 60 ? '⚠ Rogue' : '? Unknown';
    const since = d.first_seen ? d.first_seen.split('T')[0] : '—';
    const host = d.hostname || '—';
    const isMac = d.mac || '—';

    return `<tr onclick="showDeviceModal(${JSON.stringify(d).replace(/"/g, '&quot;')})">
      <td><span class="device-status ${statusCls}">${statusTxt}</span></td>
      <td class="mono">${d.ip || '—'}</td>
      <td class="mono">${isMac}</td>
      <td>${d.vendor || 'Unknown'}</td>
      <td>${host}</td>
      <td>
        <div class="risk-bar-wrap">
          <div class="risk-bar">
            <div class="risk-bar-fill" style="width:${score}%;background:${barColor}"></div>
          </div>
          <span class="risk-score-label" style="color:${barColor}">${score}</span>
        </div>
      </td>
      <td>${since}</td>
      <td onclick="event.stopPropagation()">
        ${d.is_whitelisted
        ? `<button class="btn btn-sm btn-red" onclick="removeWhitelist('${d.mac}')">Remove</button>`
        : `<button class="btn btn-sm btn-green" onclick="quickWhitelist('${d.mac}','${(d.vendor || '').replace(/'/g, "\\'")}', '${d.ip || ''}', '${(d.hostname || '').replace(/'/g, "\\'")}', ${score})">Trust</button>`
      }
      </td>
    </tr>`;
  }).join('');
}

function filterDevices() {
  const q = document.getElementById('device-search').value.toLowerCase();
  const filtered = allDevices.filter(d =>
    (d.mac || '').includes(q) || (d.ip || '').includes(q) ||
    (d.vendor || '').toLowerCase().includes(q) ||
    (d.hostname || '').toLowerCase().includes(q)
  );
  renderDevicesTable(filtered);
}

// ─────────────────────────────────────────────
//  RENDER: ALERTS
// ─────────────────────────────────────────────

function renderOverviewAlerts(alerts) {
  const el = document.getElementById('overview-alerts-feed');
  if (!el) return;
  if (!alerts.length) {
    el.innerHTML = '<div class="empty-state">No alerts yet — network looks clean ✅</div>';
    return;
  }
  el.innerHTML = alerts.map(alertHtml).join('');
}

function renderFullAlerts(alerts) {
  const el = document.getElementById('full-alerts-list');
  if (!el) return;
  const sev = document.getElementById('severity-filter')?.value || '';
  const typ = document.getElementById('type-filter')?.value || '';
  const filtered = alerts.filter(a =>
    (!sev || a.severity === sev) &&
    (!typ || a.alert_type === typ)
  );
  if (!filtered.length) {
    el.innerHTML = '<div class="empty-state">No alerts matching filters.</div>';
    return;
  }
  el.innerHTML = filtered.map(alertHtml).join('');
}

function filterAlerts() {
  renderFullAlerts(allAlerts);
}

function alertHtml(a) {
  const sev = a.severity || 'INFO';
  const time = a.timestamp ? a.timestamp.replace('T', ' ').substring(0, 19) : '—';
  
  let descText = a.description || '';
  let suppressedBadge = '';
  // Check for "[+X identical alerts suppressed]" prefix from backend
  const match = descText.match(/^\[\+(\d+) identical alerts suppressed\]\s*/);
  if (match) {
    suppressedBadge = `<span class="suppressed-badge">(${match[1]}x)</span>`;
    descText = descText.substring(match[0].length);
  }
  
  return `
    <div class="alert-item">
      <span class="alert-sev-badge sev-${sev}">${sev}</span>
      <div class="alert-body">
        <div class="alert-type">${formatAlertType(a.alert_type)}</div>
        <div class="alert-desc" title="${escHtml(descText)}">${suppressedBadge} ${escHtml(descText)}</div>
        <div class="alert-meta">
          ${a.device_mac ? `MAC: ${a.device_mac}` : ''}
          ${a.device_ip ? ` &nbsp;•&nbsp; IP: ${a.device_ip}` : ''}
          &nbsp;•&nbsp; ${time}
        </div>
      </div>
    </div>`;
}

function formatAlertType(t) {
  const map = {
    NEW_DEVICE_DETECTED: '🚨 New Unknown Device',
    ARP_SPOOF: '🎭 ARP Spoofing',
    DNS_SPOOF: '🌐 DNS Spoofing',
    MITM_DETECTED: '🕵️ MITM Attack',
    MAC_SPOOFING: '🔄 MAC Spoofing',
    ROGUE_ACCESS_POINT: '📡 Rogue Access Point',
    OPEN_AP_DETECTED: '🔓 Open AP',
    PORT_SCAN_DETECTED: '🔍 Port Scan',
    IOT_HIGH_RISK_DEVICE: '🤖 IoT High Risk',
    HIGH_PAYLOAD_ENTROPY: '📦 High Entropy / Exfil',
    BEHAVIORAL_ANOMALY: '📊 Behavioral Anomaly',
    MULTI_LAYER_CORRELATED: '🔗 Correlated Attack',
    PREDICTIVE_PRE_ALERT: '🔮 Predictive Alert',
  };
  return map[t] || t;
}

// ─────────────────────────────────────────────
//  WHITELIST
// ─────────────────────────────────────────────

async function loadWhitelist() {
  try {
    const res = await fetch('/api/whitelist');
    const data = await res.json();
    renderWhitelist(data.whitelist || {});
  } catch (_) { }
}

function renderWhitelist(wl) {
  const tbody = document.getElementById('whitelist-tbody');
  if (!tbody) return;
  const entries = Object.entries(wl);
  if (!entries.length) {
    tbody.innerHTML = '<tr><td colspan="9" class="empty-state">No trusted devices yet.</td></tr>';
    return;
  }
  tbody.innerHTML = entries.map(([mac, v]) => `
    <tr>
      <td class="mono">${mac}</td>
      <td class="mono">${v.ip || '—'}</td>
      <td>${v.hostname || '—'}</td>
      <td>${v.vendor || '—'}</td>
      <td>${v.risk_score || '0'}</td>
      <td>${v.label || '—'}</td>
      <td>${v.note || '—'}</td>
      <td>${v.added ? v.added.split('T')[0] : '—'}</td>
      <td>
        <button class="btn btn-sm btn-red" onclick="removeWhitelist('${mac}')">Remove</button>
      </td>
    </tr>`).join('');
}

async function addToWhitelist(e) {
  e.preventDefault();
  const mac = document.getElementById('wl-mac').value.trim().toLowerCase();
  const ip = document.getElementById('wl-ip').value.trim();
  const label = document.getElementById('wl-label').value.trim();
  const note = document.getElementById('wl-note').value.trim();
  try {
    const res = await fetch('/api/whitelist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mac, ip, label, note })
    });
    if (res.ok) {
      toast('✓ Device trusted: ' + mac, 'success');
      document.getElementById('wl-mac').value = '';
      document.getElementById('wl-ip').value = '';
      document.getElementById('wl-label').value = '';
      document.getElementById('wl-note').value = '';
      loadWhitelist();
      fetchDevices();
    } else {
      toast('Error adding to whitelist', 'error');
    }
  } catch (_) { toast('Request failed', 'error'); }
}

async function removeWhitelist(mac) {
  try {
    const res = await fetch(`/api/whitelist/${mac}`, { method: 'DELETE' });
    if (res.ok) {
      toast('Removed: ' + mac, 'info');
      loadWhitelist();
      fetchDevices();
    }
  } catch (_) { }
}

async function quickWhitelist(mac, vendor, ip, hostname, risk_score) {
  const label = vendor || 'Device';
  try {
    await fetch('/api/whitelist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mac, label, note: 'Added via dashboard', vendor, ip, hostname, risk_score })
    });
    toast('✓ Trusted: ' + mac, 'success');
    fetchDevices();
    fetchStats();
  } catch (_) { }
}

// ─────────────────────────────────────────────
//  SCANNER
// ─────────────────────────────────────────────

async function triggerScan() {
  const btn = document.getElementById('scan-btn');
  const scannerBtn = document.getElementById('scanner-btn');
  const ring = document.getElementById('scan-ring');
  const statusTxt = document.getElementById('scan-status-text');

  if (btn) { btn.disabled = true; btn.textContent = 'Scanning...'; }
  if (ring) ring.classList.add('scanning');
  if (statusTxt) statusTxt.textContent = 'Scanning network...';

  try {
    await fetch('/api/scan', { method: 'POST' });
    toast('🔍 Scan launched', 'info');
    // Poll for completion
    let attempts = 0;
    const check = setInterval(async () => {
      attempts++;
      try {
        const res = await fetch('/api/scan/status');
        const data = await res.json();
        if (!data.running || attempts > 30) {
          clearInterval(check);
          if (btn) { btn.disabled = false; btn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/></svg> Scan Now`; }
          if (ring) ring.classList.remove('scanning');
          if (statusTxt) statusTxt.textContent = 'Scan complete';
          if (data.last_result?.count !== undefined) {
            toast(`✅ Found ${data.last_result.count} devices`, 'success');
            showScanResults(data.last_result.devices || []);
          }
          loadAll();
        }
      } catch (_) { clearInterval(check); }
    }, 2000);
  } catch (_) {
    if (btn) { btn.disabled = false; }
    if (ring) ring.classList.remove('scanning');
    toast('Scan failed — check server', 'error');
  }
}

function showScanResults(devices) {
  const card = document.getElementById('scan-results-card');
  const cont = document.getElementById('scan-results-content');
  if (!card || !cont) return;
  card.style.display = 'block';
  if (!devices.length) { cont.innerHTML = '<div class="empty-state">No devices found.</div>'; return; }
  cont.innerHTML = `<div style="color:var(--green);margin-bottom:8px;font-size:0.9rem">Found ${devices.length} devices:</div>` +
    devices.map(d =>
      `<div style="padding:6px 0;border-bottom:1px solid var(--border)">
  <span style="color:var(--blue)">${d.ip || '?'}</span>
  &nbsp;|&nbsp; <span style="color:var(--text-secondary)">${d.mac || '?'}</span>
    &nbsp;|&nbsp; ${d.vendor || 'Unknown'}
       </div>`
    ).join('');
}

// ─────────────────────────────────────────────
//  MODAL
// ─────────────────────────────────────────────

function showDeviceModal(d) {
  const overlay = document.getElementById('modal-overlay');
  const body = document.getElementById('modal-body');
  if (!overlay || !body) return;

  const score = d.risk_score || 0;
  const barColor = score >= 80 ? '#ff3b5c' : score >= 60 ? '#ff8c42' : score >= 40 ? '#fbbf24' : '#00ff88';

  body.innerHTML = `
  <div class="detail-row"><span class="detail-label">IP Address</span><span class="detail-value">${d.ip || '—'}</span></div>
    <div class="detail-row"><span class="detail-label">MAC Address</span><span class="detail-value">${d.mac || '—'}</span></div>
    <div class="detail-row"><span class="detail-label">Vendor (OUI)</span><span class="detail-value">${d.vendor || 'Unknown'}</span></div>
    <div class="detail-row"><span class="detail-label">Hostname</span><span class="detail-value">${d.hostname || '—'}</span></div>
    <div class="detail-row"><span class="detail-label">Status</span><span class="detail-value">${d.is_whitelisted ? '✓ Whitelisted' : '⚠ Unknown'}</span></div>
    <div class="detail-row"><span class="detail-label">Risk Score</span>
      <span class="detail-value" style="color:${barColor}">${score}/100</span>
    </div>
    <div class="detail-row"><span class="detail-label">First Seen</span><span class="detail-value">${(d.first_seen || '—').replace('T', ' ').substring(0, 19)}</span></div>
    <div class="detail-row"><span class="detail-label">Last Seen</span><span class="detail-value">${(d.last_seen || '—').replace('T', ' ').substring(0, 19)}</span></div>
    <div class="detail-row"><span class="detail-label">Label</span><span class="detail-value">${d.label || '—'}</span></div>
    <div style="margin-top:16px;display:flex;gap:8px">
      ${d.is_whitelisted
      ? `<button class="btn btn-red" onclick="removeWhitelist('${d.mac}');closeModal()">Remove Trust</button>`
      : `<button class="btn btn-green" onclick="quickWhitelist('${d.mac}','${(d.vendor || '').replace(/'/g, "\\'")}','${d.ip || ''}','${(d.hostname || '').replace(/'/g, "\\'")}',${score});closeModal()">Trust Device</button>`
    }
    </div>`;

  overlay.classList.add('open');
}

function closeModal() {
  document.getElementById('modal-overlay')?.classList.remove('open');
}

// ─────────────────────────────────────────────
//  CHARTS
// ─────────────────────────────────────────────

function initCharts() {
  const tlCtx = document.getElementById('alertTimelineChart');
  if (tlCtx) {
    timelineChart = new Chart(tlCtx, {
      type: 'line',
      data: {
        labels: [],
        datasets: [{
          label: 'Alerts',
          data: [],
          fill: true,
          borderColor: '#ff3b5c',
          backgroundColor: 'rgba(255,59,92,0.08)',
          tension: 0.4,
          pointBackgroundColor: '#ff3b5c',
          pointRadius: 3,
        }, {
          label: 'New Devices',
          data: [],
          fill: true,
          borderColor: '#4da6ff',
          backgroundColor: 'rgba(77,166,255,0.06)',
          tension: 0.4,
          pointBackgroundColor: '#4da6ff',
          pointRadius: 3,
        }]
      },
      options: chartOptions('Number of Events')
    });
  }

  const sevCtx = document.getElementById('severityChart');
  if (sevCtx) {
    severityChart = new Chart(sevCtx, {
      type: 'doughnut',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
        datasets: [{
          data: [0, 0, 0, 0, 0],
          backgroundColor: ['#ff3b5c', '#ff6b80', '#ff8c42', '#4da6ff', '#00ff88'],
          borderWidth: 0,
          hoverOffset: 8,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: { color: '#7a8499', boxWidth: 12, font: { size: 11 } }
          }
        },
        cutout: '68%',
      }
    });
  }
}

function updateTimelineChart(history) {
  if (!timelineChart) return;
  const recent = history.length > 15 ? history.slice(0, 15).reverse() : history.slice().reverse();
  timelineChart.data.labels = recent.map(h => h.timestamp?.split('T')[1]?.substring(0, 5) || h.timestamp || '');
  timelineChart.data.datasets[0].data = recent.map(h => h.alerts_raised || 0);
  timelineChart.data.datasets[1].data = recent.map(h => h.new_devices || 0);
  timelineChart.update('none');
}

function updateSeverityChart(stats) {
  if (!severityChart) return;
  severityChart.data.datasets[0].data = [
    stats.CRITICAL || 0,
    stats.HIGH || 0,
    stats.MEDIUM || 0,
    stats.LOW || 0,
    stats.INFO || 0,
  ];
  severityChart.update('none');
}

function chartOptions(yLabel) {
  return {
    responsive: true,
    maintainAspectRatio: false,
    interaction: { mode: 'index', intersect: false },
    plugins: {
      legend: { labels: { color: '#7a8499', boxWidth: 12, font: { size: 11 } } }
    },
    scales: {
      x: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#4a5568', font: { size: 10 } } },
      y: {
        grid: { color: 'rgba(255,255,255,0.04)' },
        ticks: { color: '#4a5568', font: { size: 10 }, stepSize: 1 },
        title: { display: false },
        beginAtZero: true,
      }
    }
  };
}

// ─────────────────────────────────────────────
//  TAB NAVIGATION
// ─────────────────────────────────────────────

function showTab(name, el) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  const tab = document.getElementById('tab-' + name);
  if (tab) tab.classList.add('active');
  if (el) el.classList.add('active');

  const titles = {
    overview: 'Security Overview', devices: 'Connected Devices',
    alerts: 'Alert Log', 'whitelist': 'Trusted Whitelist', scanner: 'Network Scanner',
    'ap': 'Rogue AP Detection',
    'traffic': 'Traffic Analyzer',
    'reports': 'Security Reports',
    'iot': 'IoT Device Profiling', dhcp: 'DHCP Monitor',
    rtmonitor: 'RT Monitor', attacks: 'Attack Detection'
  };
  setText('page-title', titles[name] || name);

  if (name === 'whitelist') loadWhitelist();

  // Close sidebar on mobile after navigating
  if (window.innerWidth <= 768) closeSidebar();
}

// ─────────────────────────────────────────────
//  SIDEBAR TOGGLE (mobile)
// ─────────────────────────────────────────────

function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('sidebar-overlay');
  if (!sidebar) return;
  const isOpen = sidebar.classList.toggle('open');
  if (overlay) {
    if (isOpen) overlay.classList.add('active');
    else overlay.classList.remove('active');
  }
}

function closeSidebar() {
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('sidebar-overlay');
  if (sidebar) sidebar.classList.remove('open');
  if (overlay) overlay.classList.remove('active');
}

// Close sidebar on Escape key
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeSidebar();
});

// Close sidebar if window is resized above mobile breakpoint
window.addEventListener('resize', () => {
  if (window.innerWidth > 768) closeSidebar();
});

// ─────────────────────────────────────────────
//  UTILITY
// ─────────────────────────────────────────────

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function updateNavCount(id, n) {
  const el = document.getElementById(id);
  if (el) el.textContent = n;
}

function escHtml(str) {
  return (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function toast(msg, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

// ─────────────────────────────────────────────
//  REPORT GENERATION
// ─────────────────────────────────────────────

async function generateReport() {
  const btn = document.getElementById('btn-generate-report');
  const txt = document.getElementById('btn-generate-report-text');
  const toastMsg = document.getElementById('report-toast-msg');

  if (btn.disabled) return;

  btn.disabled = true;
  txt.textContent = 'Generating...';
  toastMsg.style.display = 'none';

  const formatSelect = document.getElementById('report-format-select');
  const format = formatSelect ? formatSelect.value : 'docx';

  try {
    const res = await fetch(`/api/report/generate?format=${format}`);
    if (!res.ok) throw new Error('Failed to generate report');

    // Extract filename from Content-Disposition header if possible
    let filename = `RDDS_Security_Report.${format}`;
    const disposition = res.headers.get('Content-Disposition');
    if (disposition && disposition.indexOf('filename=') !== -1) {
      const filenameRegex = /filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/;
      const matches = filenameRegex.exec(disposition);
      if (matches != null && matches[1]) {
        filename = matches[1].replace(/['"]/g, '');
      }
    }

    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);

    toastMsg.style.display = 'block';
    setTimeout(() => { toastMsg.style.display = 'none'; }, 4000);

  } catch (err) {
    console.error(err);
    alert('Error generating report: ' + err.message);
  } finally {
    btn.disabled = false;
    txt.textContent = 'Generate Report';
  }
}

/**
 * Triggers a full system reset.
 * Clears the database and restarts the monitoring engine.
 */
async function resetSystem() {
  const isConfirmed = confirm(
    "🚨 WARNING: SYSTEM RESET 🚨\n\n" +
    "This will permanently DELETE all security alerts, device logs, and scan history.\n\n" +
    "This action cannot be undone. Are you absolutely sure?"
  );

  if (!isConfirmed) return;

  try {
    const resetBtn = document.getElementById('reset-system-btn');
    resetBtn.disabled = true;
    resetBtn.innerHTML = "Cleaning...";

    const response = await fetch('/api/system/reset', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });

    const result = await response.json();

    if (result.status === 'success') {
      alert("✅ Reset Complete. The tool is now in its original state.");
      location.reload(); // Refresh the whole dashboard
    } else {
      alert("❌ Reset Failed: " + (result.error || "Unknown error"));
      resetBtn.disabled = false;
      resetBtn.innerHTML = "Reset Tool";
    }
  } catch (error) {
    console.error("System reset failed:", error);
    alert("❌ Error communicating with the server.");
    const resetBtn = document.getElementById('reset-system-btn');
    if (resetBtn) {
      resetBtn.disabled = false;
      resetBtn.innerHTML = "Reset Tool";
    }
  }
}
