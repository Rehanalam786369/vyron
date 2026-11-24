/**
 * VYRON Control Panel SPA Controller
 * 100% Closed-Loop, Zero-External-CDN Architecture
 * Native HTML5 Canvas Data Visualizations
 */

// Application State
const state = {
  devices: [],
  currentDeviceId: null,
  deviceData: null,
  apps: [],
  networkRules: [],
  logs: [],
  activeWaivers: [],
  pendingWaivers: [],
  stats: {},
  appSearchQuery: '',
  appFilterTab: 'all',
  ruleFilterTab: 'all',
  logFilterStatus: 'ALL',
  logSearchQuery: '',
  isFetching: false,
  pinAction: null, // 'guided_mode', 'uninstall_permission', 'clear_logs'
  alertTimeout: null,
};

// ============================================================================
// UTILITIES & XSS ESCAPING
// ============================================================================

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function showToast(message, type = 'info') {
  const stack = document.getElementById('toast-stack');
  if (!stack) return;

  const item = document.createElement('div');
  item.className = 'toast-item';
  item.style.backgroundColor =
    type === 'success' ? 'rgba(5, 150, 105, 0.95)' :
    type === 'error' ? 'rgba(225, 29, 72, 0.95)' :
    'rgba(2, 132, 199, 0.95)';
  item.style.color = '#fff';
  item.style.border = '1px solid rgba(255, 255, 255, 0.2)';

  item.innerHTML = `
    <span>${escapeHtml(message)}</span>
    <button style="background:none; border:none; color:#fff; cursor:pointer; margin-left:0.75rem; font-weight:bold;" onclick="this.parentElement.remove()">✕</button>
  `;

  stack.appendChild(item);
  setTimeout(() => {
    item.style.opacity = '0';
    item.style.transition = 'opacity 0.25s ease';
    setTimeout(() => item.remove(), 250);
  }, 3500);
}

function formatSeconds(sec) {
  if (sec <= 0) return 'Expired';
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  if (m >= 60) {
    const h = Math.floor(m / 60);
    const remM = m % 60;
    return `${h}h ${remM}m`;
  }
  return `${m}m ${s < 10 ? '0' : ''}${s}s`;
}

function formatIsoTime(isoStr) {
  if (!isoStr) return '';
  try {
    const d = new Date(isoStr);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  } catch (e) {
    return isoStr;
  }
}

function triggerBlockedAlert() {
  const banner = document.getElementById('blocked-alert-banner');
  if (!banner) return;
  banner.style.display = 'flex';
  if (state.alertTimeout) clearTimeout(state.alertTimeout);
  state.alertTimeout = setTimeout(() => {
    banner.style.display = 'none';
  }, 3500);
}

// ============================================================================
// NATIVE HTML5 CANVAS CHARTS (ZERO EXTERNAL CDNs)
// ============================================================================

function drawVerdictDoughnut(allowed, blocked, waived) {
  const canvas = document.getElementById('canvas-verdict');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width;
  const h = canvas.height;

  ctx.clearRect(0, 0, w, h);

  const total = allowed + blocked + waived;
  const cx = w / 2 - 35;
  const cy = h / 2;
  const radius = Math.min(cx, cy) - 15;
  const innerRadius = radius * 0.68;

  if (total === 0) {
    // Draw empty ring
    ctx.beginPath();
    ctx.arc(cx, cy, radius, 0, 2 * Math.PI);
    ctx.arc(cx, cy, innerRadius, 2 * Math.PI, 0, true);
    ctx.fillStyle = '#1e293b';
    ctx.fill();

    ctx.fillStyle = '#64748b';
    ctx.font = '12px ui-monospace, monospace';
    ctx.textAlign = 'center';
    ctx.fillText('NO DATA', cx, cy + 4);
    return;
  }

  const data = [
    { label: 'Allowed', value: allowed, color: '#10b981' },
    { label: 'Blocked', value: blocked, color: '#f43f5e' },
    { label: 'Waived', value: waived, color: '#f59e0b' }
  ];

  let startAngle = -Math.PI / 2;

  data.forEach(item => {
    if (item.value <= 0) return;
    const sliceAngle = (item.value / total) * 2 * Math.PI;

    ctx.beginPath();
    ctx.arc(cx, cy, radius, startAngle, startAngle + sliceAngle);
    ctx.arc(cx, cy, innerRadius, startAngle + sliceAngle, startAngle, true);
    ctx.closePath();
    ctx.fillStyle = item.color;
    ctx.fill();

    startAngle += sliceAngle;
  });

  // Center text (Total & Rate)
  const blockRate = total > 0 ? Math.round((blocked / total) * 100) : 0;
  ctx.fillStyle = '#ffffff';
  ctx.font = 'bold 20px ui-monospace, monospace';
  ctx.textAlign = 'center';
  ctx.fillText(blocked.toString(), cx, cy);

  ctx.fillStyle = '#94a3b8';
  ctx.font = '10px ui-sans-serif, sans-serif';
  ctx.fillText(`BLOCKED (${blockRate}%)`, cx, cy + 16);

  // Draw Legend beside doughnut
  const legX = w - 100;
  let legY = h / 2 - 30;

  data.forEach(item => {
    ctx.fillStyle = item.color;
    ctx.beginPath();
    ctx.arc(legX, legY + 5, 4, 0, 2 * Math.PI);
    ctx.fill();

    ctx.fillStyle = '#e2e8f0';
    ctx.font = '11px ui-sans-serif, sans-serif';
    ctx.textAlign = 'left';
    ctx.fillText(item.label, legX + 10, legY + 8);

    ctx.fillStyle = '#64748b';
    ctx.font = '10px ui-monospace, monospace';
    ctx.fillText(item.value.toString(), legX + 10, legY + 20);

    legY += 30;
  });
}

function drawUsageBarChart(apps) {
  const canvas = document.getElementById('canvas-usage');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width;
  const h = canvas.height;

  ctx.clearRect(0, 0, w, h);

  if (!apps || apps.length === 0) {
    ctx.fillStyle = '#64748b';
    ctx.font = '12px ui-monospace, monospace';
    ctx.textAlign = 'center';
    ctx.fillText('NO APP USAGE SYNCED YET', w / 2, h / 2);
    return;
  }

  // Take top 5
  const topList = apps.slice(0, 5);
  const maxMins = Math.max(90, ...topList.map(a => Math.max(a.last_usage_minutes || 0, a.daily_limit_minutes || 0)));

  const startX = 110;
  const barMaxWidth = w - startX - 85;
  const startY = 22;
  const rowHeight = 36;

  topList.forEach((app, i) => {
    const y = startY + i * rowHeight;
    const used = app.last_usage_minutes || 0;
    const limit = app.daily_limit_minutes || 0;
    const barWidth = Math.max(4, (used / maxMins) * barMaxWidth);

    // Label App Name
    ctx.fillStyle = '#e2e8f0';
    ctx.font = '11px ui-sans-serif, sans-serif';
    ctx.textAlign = 'right';
    const cleanName = (app.app_name || app.package_name).length > 13
      ? (app.app_name || app.package_name).substring(0, 12) + '…'
      : (app.app_name || app.package_name);
    ctx.fillText(cleanName, startX - 10, y + 14);

    // Background track
    ctx.fillStyle = '#1e293b';
    ctx.beginPath();
    ctx.roundRect(startX, y + 3, barMaxWidth, 16, 4);
    ctx.fill();

    // Usage Fill (Rose if over limit, else Cyan)
    const isOver = limit > 0 && used >= limit;
    ctx.fillStyle = isOver ? '#f43f5e' : (used > 40 ? '#06b6d4' : '#38bdf8');
    ctx.beginPath();
    ctx.roundRect(startX, y + 3, Math.min(barWidth, barMaxWidth), 16, 4);
    ctx.fill();

    // Limit marker line if applicable
    if (limit > 0) {
      const markX = startX + (limit / maxMins) * barMaxWidth;
      ctx.strokeStyle = '#f59e0b';
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo(markX, y);
      ctx.lineTo(markX, y + 22);
      ctx.stroke();
    }

    // Number text
    ctx.fillStyle = isOver ? '#fb7185' : '#94a3b8';
    ctx.font = '10px ui-monospace, monospace';
    ctx.textAlign = 'left';
    const textLabel = limit > 0 ? `${used}m / ${limit}m` : `${used}m`;
    ctx.fillText(textLabel, startX + barMaxWidth + 8, y + 15);
  });
}

// ============================================================================
// DATA FETCHING & SYNCHRONIZATION
// ============================================================================

async function checkDatabaseHealth() {
  try {
    const res = await fetch('/api/health');
    const data = await res.json();
    const pill = document.getElementById('db-health-pill');
    const dot = document.getElementById('db-health-dot');
    const text = document.getElementById('db-health-text');

    if (res.ok && data.status === 'ok') {
      if (pill) pill.className = 'pill pill-emerald';
      if (dot) dot.style.backgroundColor = '#10b981';
      if (text) text.textContent = 'DB: LIVE';
    } else {
      if (pill) pill.className = 'pill pill-rose';
      if (dot) dot.style.backgroundColor = '#f43f5e';
      if (text) text.textContent = 'DB: ERROR';
    }
  } catch (err) {
    const pill = document.getElementById('db-health-pill');
    const dot = document.getElementById('db-health-dot');
    const text = document.getElementById('db-health-text');
    if (pill) pill.className = 'pill pill-rose';
    if (dot) dot.style.backgroundColor = '#f43f5e';
    if (text) text.textContent = 'DB: DOWN';
  }
}

async function fetchDevicesList() {
  try {
    const res = await fetch('/api/devices');
    if (!res.ok) throw new Error('Failed to load devices');
    state.devices = await res.json();

    const selector = document.getElementById('device-selector');
    if (!selector) return;

    selector.innerHTML = '';
    state.devices.forEach(d => {
      const opt = document.createElement('option');
      opt.value = d.id;
      opt.textContent = `${d.device_name} (${d.is_paired ? 'Paired' : 'Unpaired'})`;
      selector.appendChild(opt);
    });

    if (state.devices.length > 0) {
      if (!state.currentDeviceId || !state.devices.some(d => d.id === state.currentDeviceId)) {
        state.currentDeviceId = state.devices[0].id;
      }
      selector.value = state.currentDeviceId;
    }
  } catch (err) {
    console.error('Fetch devices error:', err);
  }
}

async function fetchDeviceData() {
  if (!state.currentDeviceId || state.isFetching) return;
  state.isFetching = true;

  try {
    // 1. Fetch Consolidated Telemetry
    const resTelem = await fetch(`/api/devices/${state.currentDeviceId}/telemetry`);
    if (resTelem.ok) {
      const telem = await resTelem.json();
      state.deviceData = telem.device;
      state.stats = telem.stats;
      state.pendingWaivers = telem.pending_waivers || [];
      state.activeWaivers = telem.active_waivers || [];
      state.logs = telem.logs || [];

      renderDeviceCard(state.deviceData);
      renderKPIs(state.stats, state.deviceData);
      renderWaiversInbox(state.pendingWaivers, state.activeWaivers);
      drawVerdictDoughnut(state.stats.allowed_logs || 0, state.stats.blocked_logs || 0, state.stats.waived_logs || 0);
      drawUsageBarChart(telem.top_apps || []);
      renderLogsTable(state.logs);
    }

    // 2. Fetch Installed Apps & Policies
    const resApps = await fetch(`/api/devices/${state.currentDeviceId}/apps`);
    if (resApps.ok) {
      state.apps = await resApps.json();
      renderAppsTable();
    }

    // 3. Fetch Network Rules
    const resRules = await fetch(`/api/devices/${state.currentDeviceId}/network-rules`);
    if (resRules.ok) {
      state.networkRules = await resRules.json();
      renderNetworkRulesTable();
    }

  } catch (err) {
    console.error('Dashboard telemetry poll error:', err);
  } finally {
    state.isFetching = false;
  }
}

// ============================================================================
// RENDERING FUNCTIONS
// ============================================================================

function renderDeviceCard(dev) {
  if (!dev) return;

  const nameEl = document.getElementById('card-device-name');
  const modelEl = document.getElementById('card-device-model');
  const keyEl = document.getElementById('card-pairing-key');
  const pairedEl = document.getElementById('card-paired-status');
  const lastSeenEl = document.getElementById('card-last-seen');

  if (nameEl) nameEl.textContent = dev.device_name;
  if (modelEl) modelEl.textContent = `Model: ${dev.device_model || 'Pending initial handshake'}`;
  if (keyEl) keyEl.textContent = dev.pairing_key;

  if (pairedEl) {
    if (dev.is_paired) {
      pairedEl.className = 'pill pill-emerald';
      pairedEl.textContent = 'PAIRED & ONLINE';
    } else {
      pairedEl.className = 'pill pill-amber';
      pairedEl.textContent = 'AWAITING APP PAIRING';
    }
  }

  if (lastSeenEl) {
    lastSeenEl.textContent = dev.last_seen_at ? `Last Synced: ${formatIsoTime(dev.last_seen_at)} UTC` : 'Last Synced: Never';
  }

  // Guided Mode Toggle Button
  const guidedBadge = document.getElementById('guided-mode-badge');
  const btnGuided = document.getElementById('btn-toggle-guided');
  if (dev.guided_mode) {
    if (guidedBadge) {
      guidedBadge.className = 'pill pill-emerald';
      guidedBadge.textContent = 'GUIDED MODE: LOCKED';
    }
    if (btnGuided) {
      btnGuided.className = 'btn btn-rose btn-sm';
      btnGuided.textContent = 'Unlock Handover';
    }
  } else {
    if (guidedBadge) {
      guidedBadge.className = 'pill pill-slate';
      guidedBadge.textContent = 'GUIDED MODE: OFF';
    }
    if (btnGuided) {
      btnGuided.className = 'btn btn-cyan btn-sm';
      btnGuided.textContent = 'Lock Handover';
    }
  }

  // Uninstall Lock Widget
  const uninstPill = document.getElementById('uninstall-pill');
  const btnUninst = document.getElementById('btn-uninstall-action');

  if (dev.uninstall_allowed) {
    if (uninstPill) {
      uninstPill.className = 'pill pill-amber';
      uninstPill.textContent = `UNINSTALL UNLOCKED (${formatSeconds(dev.uninstall_remaining_seconds)})`;
    }
    if (btnUninst) {
      btnUninst.className = 'btn btn-rose btn-sm';
      btnUninst.textContent = 'Revoke Now';
    }
  } else {
    if (uninstPill) {
      uninstPill.className = 'pill pill-rose';
      uninstPill.textContent = 'UNINSTALL: PROTECTED';
    }
    if (btnUninst) {
      btnUninst.className = 'btn btn-dark btn-sm';
      btnUninst.textContent = 'Unlock (10m)';
    }
  }
}

function renderKPIs(stats, dev) {
  if (!stats) return;

  const kpiApps = document.getElementById('kpi-apps-count');
  const kpiPolicies = document.getElementById('kpi-policies-count');
  const kpiBlocked = document.getElementById('kpi-blocked-count');
  const kpiTotalLogs = document.getElementById('kpi-total-logs-count');
  const kpiWaivers = document.getElementById('kpi-waivers-count');
  const kpiPending = document.getElementById('kpi-pending-waivers');
  const kpiUninst = document.getElementById('kpi-uninstall-status');

  if (kpiApps) kpiApps.textContent = state.apps.length;
  if (kpiPolicies) kpiPolicies.textContent = state.apps.filter(a => a.has_policy && a.is_active).length;
  if (kpiBlocked) kpiBlocked.textContent = stats.blocked_logs || 0;
  if (kpiTotalLogs) kpiTotalLogs.textContent = stats.total_logs || 0;
  if (kpiWaivers) kpiWaivers.textContent = stats.active_waivers_count || 0;
  if (kpiPending) kpiPending.textContent = stats.pending_waivers_count || 0;

  if (kpiUninst) {
    kpiUninst.textContent = dev && dev.uninstall_allowed ? 'UNLOCKED' : 'LOCKED';
    kpiUninst.style.color = dev && dev.uninstall_allowed ? '#f59e0b' : '#fb7185';
  }
}

function renderWaiversInbox(pending, active) {
  const inboxSection = document.getElementById('waiver-inbox-section');
  const countBadge = document.getElementById('pending-waiver-count');
  const cardsContainer = document.getElementById('pending-waiver-cards');

  if (pending && pending.length > 0) {
    inboxSection.style.display = 'block';
    countBadge.textContent = `${pending.length} PENDING`;

    let html = '';
    pending.forEach(w => {
      html += `
        <div class="flex items-center justify-between flex-wrap gap-2 p-2" style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(245, 158, 11, 0.4); border-radius: 8px;">
          <div>
            <div class="flex items-center gap-2">
              <span class="pill pill-amber">${escapeHtml(w.target_type.toUpperCase())}</span>
              <strong style="color: #fff; font-size: 0.85rem;">${escapeHtml(w.display_name)}</strong>
              <span style="font-size: 0.75rem; color: #94a3b8; font-family: var(--font-mono);">${escapeHtml(w.target)}</span>
            </div>
            <div style="font-size: 0.75rem; color: #fef08a; margin-top: 0.15rem;">
              Reason: "${escapeHtml(w.reason)}" · Requested Duration: ${w.duration_minutes}m
            </div>
          </div>
          <div class="flex items-center gap-1.5">
            <button type="button" class="btn btn-emerald btn-sm" onclick="handleWaiverAction(${w.id}, 'APPROVE', 10)">Approve 10m</button>
            <button type="button" class="btn btn-cyan btn-sm" onclick="handleWaiverAction(${w.id}, 'APPROVE', 5)">5m</button>
            <button type="button" class="btn btn-purple btn-sm" onclick="handleWaiverAction(${w.id}, 'APPROVE', 15)">15m</button>
            <button type="button" class="btn btn-rose btn-sm" onclick="handleWaiverAction(${w.id}, 'DENY')">Deny</button>
          </div>
        </div>
      `;
    });
    cardsContainer.innerHTML = html;
  } else {
    inboxSection.style.display = 'none';
  }

  // Active Waivers Row
  const activeRow = document.getElementById('active-waivers-row');
  const activePillsContainer = document.getElementById('active-waiver-pills');

  if (active && active.length > 0) {
    activeRow.style.display = 'block';
    let pillsHtml = '';
    active.forEach(w => {
      pillsHtml += `
        <div class="flex items-center gap-2" style="background: rgba(15, 23, 42, 0.8); border: 1px solid rgba(16, 185, 129, 0.5); padding: 0.2rem 0.5rem; border-radius: 6px; font-size: 0.75rem;">
          <strong style="color: #fff;">${escapeHtml(w.display_name)}</strong>
          <span class="pill pill-emerald waiver-countdown-pill" data-waiver-id="${w.id}">${formatSeconds(w.remaining_seconds)}</span>
          <button type="button" class="btn btn-rose btn-sm" style="padding: 0.1rem 0.35rem; font-size: 0.68rem;" onclick="revokeWaiver(${w.id})">Revoke</button>
        </div>
      `;
    });
    activePillsContainer.innerHTML = pillsHtml;
  } else {
    activeRow.style.display = 'none';
  }
}

function renderAppsTable() {
  const tbody = document.getElementById('apps-table-body');
  if (!tbody) return;

  const filter = state.appFilterTab;
  const q = state.appSearchQuery.toLowerCase();

  const filtered = state.apps.filter(app => {
    // Mode filter
    const mode = app.policy_mode || 'ALLOW';
    const isRestricted = app.has_policy && app.is_active && mode !== 'ALLOW';

    if (filter === 'restricted' && !isRestricted) return false;
    if (filter === 'scheduled' && mode !== 'SCHEDULE') return false;
    if (filter === 'unrestricted' && isRestricted) return false;

    // Search query
    if (q) {
      const matchName = (app.app_name || '').toLowerCase().includes(q);
      const matchPkg = (app.package_name || '').toLowerCase().includes(q);
      if (!matchName && !matchPkg) return false;
    }
    return true;
  });

  // Update counts
  const totalEl = document.getElementById('apps-total-badge');
  const countAll = document.getElementById('count-all-apps');
  const countRestricted = document.getElementById('count-restricted-apps');
  const countScheduled = document.getElementById('count-scheduled-apps');
  const countUnrestricted = document.getElementById('count-unrestricted-apps');

  if (totalEl) totalEl.textContent = `${state.apps.length} APPS`;
  if (countAll) countAll.textContent = state.apps.length;
  if (countRestricted) countRestricted.textContent = state.apps.filter(a => a.has_policy && a.is_active && a.policy_mode !== 'ALLOW').length;
  if (countScheduled) countScheduled.textContent = state.apps.filter(a => a.policy_mode === 'SCHEDULE').length;
  if (countUnrestricted) countUnrestricted.textContent = state.apps.filter(a => !a.has_policy || !a.is_active || a.policy_mode === 'ALLOW').length;

  if (filtered.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" style="text-align: center; color: var(--text-dim); padding: 2rem 0;">
          No apps match the current filter or search criteria.
        </td>
      </tr>
    `;
    return;
  }

  let html = '';
  filtered.forEach(app => {
    const pkg = escapeHtml(app.package_name);
    const name = escapeHtml(app.app_name || app.package_name);
    const mode = app.policy_mode || 'ALLOW';
    const used = app.last_usage_minutes || 0;
    const limit = app.daily_limit_minutes || 0;

    // Badge for Policy Mode
    let modeBadge = '<span class="pill pill-slate">ALLOW</span>';
    if (app.has_policy && app.is_active) {
      if (mode === 'BLOCK') modeBadge = '<span class="pill pill-rose">FULL BLOCK</span>';
      else if (mode === 'SCHEDULE') modeBadge = '<span class="pill pill-purple">SCHEDULED</span>';
      else if (mode === 'DAILY_LIMIT') modeBadge = '<span class="pill pill-cyan">DAILY QUOTA</span>';
    }

    // Schedule / Quota details
    let detailText = '<span style="color: var(--text-dim);">None</span>';
    if (app.has_policy && app.is_active) {
      if (mode === 'SCHEDULE') {
        detailText = `<span class="font-mono text-purple" style="color: #c084fc;">${escapeHtml(app.schedule_start)} – ${escapeHtml(app.schedule_end)}</span>`;
      } else if (mode === 'DAILY_LIMIT') {
        const isExceeded = limit > 0 && used >= limit;
        detailText = `<span class="font-mono" style="color: ${isExceeded ? '#fb7185' : '#38bdf8'}; font-weight: bold;">${used}m / ${limit}m limit</span>`;
      } else if (mode === 'BLOCK') {
        detailText = `<span style="color: #fb7185; font-size: 0.75rem;">Restricted 24/7</span>`;
      }
    }

    // Active Toggle Switch
    const checked = (app.has_policy && app.is_active) ? 'checked' : '';

    // Quick Waiver Button if currently restricted
    let waiverBtn = '';
    if (app.has_policy && app.is_active && mode !== 'ALLOW') {
      if (app.has_active_waiver) {
        waiverBtn = `<span class="pill pill-emerald" style="font-size: 0.68rem;">Waived (${formatSeconds(app.waiver_remaining_seconds)})</span>`;
      } else {
        waiverBtn = `<button type="button" class="btn btn-amber btn-sm" style="font-size: 0.7rem; padding: 0.2rem 0.45rem;" onclick="grantQuickAppWaiver('${pkg}', '${name}')">10m Waiver</button>`;
      }
    }

    html += `
      <tr>
        <td>
          <div style="font-weight: 700; color: #fff;">${name}</div>
          <div style="font-size: 0.72rem; color: var(--text-dim); font-family: var(--font-mono);">${pkg}</div>
        </td>
        <td>
          <span class="font-mono" style="color: ${used > 30 ? '#38bdf8' : 'var(--text-muted)'}; font-weight: 600;">${used} mins</span>
        </td>
        <td>${modeBadge}</td>
        <td>${detailText}</td>
        <td>
          <label class="switch">
            <input type="checkbox" ${checked} onchange="toggleAppPolicy('${pkg}', this.checked)">
            <span class="slider"></span>
          </label>
        </td>
        <td style="text-align: right;">
          <div class="flex items-center justify-center gap-1.5" style="justify-content: flex-end;">
            ${waiverBtn}
            <button type="button" class="btn btn-dark btn-sm" onclick="openConfigurePolicyModal('${pkg}', '${name}', '${mode}', '${app.schedule_start || ''}', '${app.schedule_end || ''}', ${limit || 60}, ${app.is_active ? 'true' : 'false'})">
              Configure
            </button>
          </div>
        </td>
      </tr>
    `;
  });

  tbody.innerHTML = html;
}

function renderNetworkRulesTable() {
  const tbody = document.getElementById('rules-table-body');
  const countBadge = document.getElementById('rules-count-badge');
  if (!tbody) return;

  const tab = state.ruleFilterTab;
  const filtered = state.networkRules.filter(r => {
    if (tab === 'timed' && !r.expires_at) return false;
    if (tab !== 'all' && tab !== 'timed' && r.rule_type !== tab) return false;
    return true;
  });

  if (countBadge) countBadge.textContent = `${state.networkRules.length} RULES`;

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-dim); padding: 1.5rem 0;">No matching network rules.</td></tr>`;
    return;
  }

  let html = '';
  filtered.forEach(r => {
    const isBlock = r.action === 'BLOCK';
    const actionBadge = isBlock ? '<span class="pill pill-rose">BLOCK</span>' : '<span class="pill pill-emerald">ALLOW</span>';
    const typeBadge = `<span class="pill pill-slate">${escapeHtml(r.rule_type.toUpperCase())}</span>`;

    let expiryDesc = escapeHtml(r.note || 'Permanent');
    if (r.expires_at) {
      expiryDesc = `<span class="pill pill-amber" style="font-size: 0.7rem;">${formatSeconds(r.remaining_seconds)}</span>`;
    }

    const checked = r.is_active ? 'checked' : '';

    html += `
      <tr>
        <td>${typeBadge}</td>
        <td style="font-family: var(--font-mono); font-weight: 600; color: #fff;">${escapeHtml(r.target)}</td>
        <td>${actionBadge}</td>
        <td>${expiryDesc}</td>
        <td>
          <label class="switch">
            <input type="checkbox" ${checked} onchange="toggleNetworkRule(${r.id})">
            <span class="slider"></span>
          </label>
        </td>
        <td style="text-align: right;">
          <button type="button" class="btn btn-rose btn-sm" onclick="deleteNetworkRule(${r.id})">Delete</button>
        </td>
      </tr>
    `;
  });

  tbody.innerHTML = html;
}

function renderLogsTable(logs) {
  const container = document.getElementById('logs-feed-container');
  const countBadge = document.getElementById('logs-count-badge');
  if (!container) return;

  const filter = state.logFilterStatus;
  const q = state.logSearchQuery.toLowerCase();

  const filtered = logs.filter(l => {
    if (filter !== 'ALL' && l.status !== filter) return false;
    if (q) {
      const matchTarget = (l.target || '').toLowerCase().includes(q);
      const matchReason = (l.reason || '').toLowerCase().includes(q);
      if (!matchTarget && !matchReason) return false;
    }
    return true;
  });

  if (countBadge) countBadge.textContent = `${logs.length} LOGS`;

  if (filtered.length === 0) {
    container.innerHTML = `<div style="text-align: center; color: var(--text-dim); padding: 1.5rem 0; font-size: 0.8rem;">No telemetry matching criteria.</div>`;
    return;
  }

  let html = '';
  filtered.forEach(l => {
    const isBlock = l.status === 'BLOCKED';
    const isWaived = l.status === 'WAIVED';
    const pillClass = isBlock ? 'pill-rose' : (isWaived ? 'pill-amber' : 'pill-emerald');

    html += `
      <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid ${isBlock ? 'rgba(244, 63, 94, 0.3)' : 'rgba(51, 65, 85, 0.5)'}; border-radius: 6px; padding: 0.4rem 0.6rem; font-size: 0.75rem;">
        <div class="flex items-center justify-between mb-0.5">
          <div class="flex items-center gap-1.5">
            <span style="color: var(--text-dim); font-family: var(--font-mono); font-size: 0.7rem;">${formatIsoTime(l.created_at)}</span>
            <span class="pill pill-slate" style="font-size: 0.68rem; padding: 0.1rem 0.4rem;">${escapeHtml(l.event_type.toUpperCase())}</span>
            <strong style="color: #fff; font-family: var(--font-mono);">${escapeHtml(l.target)}</strong>
          </div>
          <span class="pill ${pillClass}" style="font-size: 0.68rem;">${escapeHtml(l.status)}</span>
        </div>
        <div style="color: var(--text-muted); font-size: 0.72rem;">${escapeHtml(l.reason)}</div>
      </div>
    `;
  });

  container.innerHTML = html;
}

// ============================================================================
// SECOND-BY-SECOND COUNTDOWN TICKER
// ============================================================================

function startCountdownTicker() {
  setInterval(() => {
    let shouldSync = false;

    // 1. Decrement active emergency waivers
    if (state.activeWaivers && state.activeWaivers.length > 0) {
      state.activeWaivers.forEach(w => {
        if (w.remaining_seconds > 0) {
          w.remaining_seconds -= 1;
          if (w.remaining_seconds === 0) shouldSync = true;
        }
      });
      // Update DOM pills
      document.querySelectorAll('.waiver-countdown-pill').forEach(pill => {
        const id = parseInt(pill.getAttribute('data-waiver-id'), 10);
        const w = state.activeWaivers.find(x => x.id === id);
        if (w) pill.textContent = formatSeconds(w.remaining_seconds);
      });
    }

    // 2. Decrement temporary network rules
    if (state.networkRules && state.networkRules.length > 0) {
      state.networkRules.forEach(r => {
        if (r.remaining_seconds !== null && r.remaining_seconds > 0) {
          r.remaining_seconds -= 1;
          if (r.remaining_seconds === 0) shouldSync = true;
        }
      });
    }

    // 3. Decrement uninstall permission window
    if (state.deviceData && state.deviceData.uninstall_allowed && state.deviceData.uninstall_remaining_seconds > 0) {
      state.deviceData.uninstall_remaining_seconds -= 1;
      const uninstPill = document.getElementById('uninstall-pill');
      if (uninstPill) {
        uninstPill.textContent = `UNINSTALL UNLOCKED (${formatSeconds(state.deviceData.uninstall_remaining_seconds)})`;
      }
      if (state.deviceData.uninstall_remaining_seconds === 0) {
        shouldSync = true;
      }
    }

    if (shouldSync) {
      fetchDeviceData();
    }
  }, 1000);
}

// ============================================================================
// USER ACTIONS & MODAL HANDLERS
// ============================================================================

function handleDeviceSwitch(devId) {
  state.currentDeviceId = parseInt(devId, 10);
  fetchDeviceData();
}

function copyPairingKey() {
  const key = document.getElementById('card-pairing-key')?.textContent;
  if (key) {
    navigator.clipboard.writeText(key).then(() => {
      showToast(`Pairing Key ${key} copied to clipboard!`, 'success');
    }).catch(() => {
      showToast(`Key: ${key}`, 'info');
    });
  }
}

async function regenerateDeviceKey() {
  if (!confirm('Regenerating this key will disconnect any previously paired phone until the new key is entered. Continue?')) {
    return;
  }
  try {
    const res = await fetch(`/api/devices/${state.currentDeviceId}/regenerate-key`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to regenerate key');
    showToast(`New Identity Key generated: ${data.pairing_key}`, 'success');
    await fetchDevicesList();
    await fetchDeviceData();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

function promptGuidedModeToggle() {
  const targetState = !state.deviceData?.guided_mode;
  state.pinAction = {
    type: 'guided_mode',
    targetState: targetState
  };
  openPinModal(
    targetState ? 'Enable Guided Handover Lock' : 'Disable Guided Handover Lock',
    targetState ? 'Enforce strict network and app control policies on target device.' : 'Temporarily unlock governance rules using Supervisor PIN.'
  );
}

function handleUninstallAction() {
  if (state.deviceData?.uninstall_allowed) {
    // Revoke
    fetch(`/api/devices/${state.currentDeviceId}/revoke-uninstall`, { method: 'POST' })
      .then(res => res.json())
      .then(() => {
        showToast('Uninstall protection re-locked immediately', 'info');
        fetchDeviceData();
      });
  } else {
    // Unlock permission (prompt PIN)
    state.pinAction = { type: 'uninstall_permission' };
    openPinModal('Grant Uninstall Permission', 'Authorizes the target device to be uninstalled for 10 minutes.');
  }
}

function promptClearLogs() {
  if (state.deviceData?.guided_mode) {
    state.pinAction = { type: 'clear_logs' };
    openPinModal('Supervisor Verification Required', 'Guided Mode is active. Enter Supervisor PIN to purge telemetry logs.');
  } else {
    if (confirm('Are you sure you want to clear all network telemetry logs?')) {
      executeClearLogs('');
    }
  }
}

function openPinModal(title, desc) {
  document.getElementById('modal-pin-title').textContent = title;
  document.getElementById('modal-pin-desc').textContent = desc;
  document.getElementById('input-supervisor-pin').value = '';
  document.getElementById('modal-pin-error').style.display = 'none';
  document.getElementById('modal-pin').classList.remove('hidden');
  document.getElementById('input-supervisor-pin').focus();
}

function closeModal(modalId) {
  document.getElementById(modalId)?.classList.add('hidden');
}

function handleBackdropClick(e, modalId) {
  if (e.target.id === modalId) {
    closeModal(modalId);
  }
}

async function executePinAction() {
  const pin = document.getElementById('input-supervisor-pin').value.trim();
  const errBox = document.getElementById('modal-pin-error');
  if (!pin) {
    errBox.textContent = 'Please enter your Supervisor PIN';
    errBox.style.display = 'block';
    return;
  }

  const action = state.pinAction;
  if (!action) return;

  try {
    if (action.type === 'guided_mode') {
      const res = await fetch(`/api/devices/${state.currentDeviceId}/guided-mode`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pin, enabled: action.targetState })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Authentication failed');

      showToast(`Guided Mode ${data.guided_mode ? 'LOCKED' : 'UNLOCKED'}`, 'success');
      closeModal('modal-pin');
      await fetchDeviceData();

    } else if (action.type === 'uninstall_permission') {
      const res = await fetch(`/api/devices/${state.currentDeviceId}/uninstall-permission`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pin })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Authentication failed');

      showToast('Uninstall protection unlocked for 10 minutes', 'success');
      closeModal('modal-pin');
      await fetchDeviceData();

    } else if (action.type === 'clear_logs') {
      executeClearLogs(pin);
    }
  } catch (err) {
    errBox.textContent = err.message;
    errBox.style.display = 'block';
  }
}

async function executeClearLogs(pin) {
  try {
    const res = await fetch(`/api/devices/${state.currentDeviceId}/logs`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pin })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to clear logs');

    showToast('Telemetry logs purged', 'success');
    closeModal('modal-pin');
    await fetchDeviceData();
  } catch (err) {
    const errBox = document.getElementById('modal-pin-error');
    if (errBox) {
      errBox.textContent = err.message;
      errBox.style.display = 'block';
    } else {
      showToast(err.message, 'error');
    }
  }
}

// ============================================================================
// WAIVER ACTIONS
// ============================================================================

async function handleWaiverAction(waiverId, action, durationMins = 10) {
  try {
    const res = await fetch(`/api/waivers/${waiverId}/action`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action, duration_minutes: durationMins })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to process waiver');

    showToast(`Waiver ${data.waiver_status === 'APPROVED' ? 'Approved for ' + durationMins + 'm' : 'Denied'}`, 'success');
    await fetchDeviceData();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function revokeWaiver(waiverId) {
  try {
    const res = await fetch(`/api/waivers/${waiverId}/revoke`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to revoke waiver');

    showToast('Waiver revoked early', 'info');
    await fetchDeviceData();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function grantQuickAppWaiver(pkg, name) {
  try {
    const res = await fetch(`/api/devices/${state.currentDeviceId}/waivers/grant`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target_type: 'app',
        target: pkg,
        display_name: name,
        duration_minutes: 10
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to grant waiver');

    showToast(`10-minute Emergency Waiver granted for ${name}`, 'success');
    await fetchDeviceData();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// ============================================================================
// APP POLICY MANAGEMENT
// ============================================================================

function filterApps(tab) {
  state.appFilterTab = tab;
  document.querySelectorAll('#apps-filter-tabs .tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-filter') === tab);
  });
  renderAppsTable();
}

function handleAppSearch(query) {
  state.appSearchQuery = query.trim();
  renderAppsTable();
}

function openConfigurePolicyModal(pkg, name, mode, start, end, limitMins, isActive) {
  document.getElementById('policy-pkg').value = pkg;
  document.getElementById('policy-display-name').value = name;
  document.getElementById('policy-modal-appname').textContent = `${name} (${pkg})`;
  document.getElementById('policy-mode').value = mode;
  document.getElementById('policy-start').value = start || '16:00';
  document.getElementById('policy-end').value = end || '21:00';
  document.getElementById('policy-limit-mins').value = limitMins || 60;
  document.getElementById('policy-active').checked = isActive;

  handlePolicyModeChange(mode);
  document.getElementById('modal-policy').classList.remove('hidden');
}

function handlePolicyModeChange(mode) {
  document.getElementById('policy-schedule-fields').style.display = mode === 'SCHEDULE' ? 'grid' : 'none';
  document.getElementById('policy-limit-fields').style.display = mode === 'DAILY_LIMIT' ? 'block' : 'none';
}

async function handleSavePolicy(e) {
  e.preventDefault();
  const pkg = document.getElementById('policy-pkg').value;
  const name = document.getElementById('policy-display-name').value;
  const mode = document.getElementById('policy-mode').value;
  const start = document.getElementById('policy-start').value.trim();
  const end = document.getElementById('policy-end').value.trim();
  const limitMins = parseInt(document.getElementById('policy-limit-mins').value, 10);
  const isActive = document.getElementById('policy-active').checked;

  try {
    const res = await fetch(`/api/devices/${state.currentDeviceId}/apps/policy`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        package_name: pkg,
        app_name: name,
        policy_mode: mode,
        schedule_start: start,
        schedule_end: end,
        daily_limit_minutes: limitMins,
        is_active: isActive
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to save policy');

    showToast(`Policy updated for ${name}`, 'success');
    closeModal('modal-policy');
    await fetchDeviceData();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function toggleAppPolicy(pkg, newActiveState) {
  try {
    const res = await fetch(`/api/devices/${state.currentDeviceId}/apps/${encodeURIComponent(pkg)}/toggle`, {
      method: 'PATCH'
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to toggle policy');

    showToast(`Policy is now ${data.is_active ? 'Active' : 'Paused'}`, 'info');
    await fetchDeviceData();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

function openAddManualAppModal() {
  document.getElementById('manual-app-pkg').value = '';
  document.getElementById('manual-app-name').value = '';
  document.getElementById('modal-add-app').classList.remove('hidden');
}

async function handleManualAppSubmit(e) {
  e.preventDefault();
  const pkg = document.getElementById('manual-app-pkg').value.trim();
  const name = document.getElementById('manual-app-name').value.trim();

  try {
    const res = await fetch(`/api/devices/${state.currentDeviceId}/apps/manual`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ package_name: pkg, app_name: name })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to add app');

    showToast(`Registered app ${data.app_name}`, 'success');
    closeModal('modal-add-app');
    await fetchDeviceData();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// ============================================================================
// NETWORK RULES (DNS / IP)
// ============================================================================

function handleRuleTypeChange(type) {
  const targetInput = document.getElementById('rule-target');
  if (type === 'domain') {
    targetInput.placeholder = 'e.g. instagram.com or reels.instagram.com';
  } else {
    targetInput.placeholder = 'e.g. 157.240.22.174';
  }
}

function filterRules(tab) {
  state.ruleFilterTab = tab;
  document.querySelectorAll('#rules-filter-tabs .tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-tab') === tab);
  });
  renderNetworkRulesTable();
}

async function handleAddNetworkRule(e) {
  e.preventDefault();
  const type = document.getElementById('rule-type').value;
  const action = document.getElementById('rule-action').value;
  const target = document.getElementById('rule-target').value.trim();
  const duration = document.getElementById('rule-duration').value;
  const note = document.getElementById('rule-note').value.trim();

  try {
    const res = await fetch(`/api/devices/${state.currentDeviceId}/network-rules`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        rule_type: type,
        action: action,
        target: target,
        duration_mins: duration ? parseInt(duration, 10) : null,
        note: note
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to deploy rule');

    showToast(`Network rule deployed for ${data.target}`, 'success');
    document.getElementById('rule-target').value = '';
    document.getElementById('rule-note').value = '';
    await fetchDeviceData();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function toggleNetworkRule(ruleId) {
  try {
    const res = await fetch(`/api/network-rules/${ruleId}/toggle`, { method: 'PATCH' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to toggle rule');

    showToast(`Rule #${ruleId} is now ${data.is_active ? 'Active' : 'Paused'}`, 'info');
    await fetchDeviceData();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function deleteNetworkRule(ruleId) {
  if (!confirm(`Delete rule #${ruleId}?`)) return;
  try {
    const res = await fetch(`/api/network-rules/${ruleId}`, { method: 'DELETE' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to delete rule');

    showToast(`Rule #${ruleId} deleted`, 'success');
    await fetchDeviceData();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// ============================================================================
// SIMULATOR & LOGS
// ============================================================================

function setSimPreset(type, target, time, used) {
  document.getElementById('sim-type').value = type;
  document.getElementById('sim-target').value = target;
  document.getElementById('sim-time').value = time;
  document.getElementById('sim-used-mins').value = used;
  document.getElementById('form-simulate')?.dispatchEvent(new Event('submit'));
}

async function handleSimulate(e) {
  e.preventDefault();
  const type = document.getElementById('sim-type').value;
  const target = document.getElementById('sim-target').value.trim();
  const time = document.getElementById('sim-time').value.trim() || '12:00';
  const used = parseInt(document.getElementById('sim-used-mins').value || '0', 10);

  try {
    const res = await fetch(`/api/devices/${state.currentDeviceId}/simulate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: type,
        target: target,
        sim_time: time,
        sim_used_mins: used
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Simulation failed');

    const box = document.getElementById('sim-verdict-box');
    const badge = document.getElementById('sim-verdict-badge');
    const timeEl = document.getElementById('sim-verdict-time');
    const targetEl = document.getElementById('sim-verdict-target');
    const reasonEl = document.getElementById('sim-verdict-reason');

    box.style.display = 'block';
    targetEl.textContent = data.target;
    reasonEl.textContent = data.reason;
    timeEl.textContent = `SIM TIME: ${data.sim_time}`;

    if (data.status === 'BLOCKED') {
      box.style.backgroundColor = 'rgba(244, 63, 94, 0.2)';
      box.style.border = '1px solid rgba(244, 63, 94, 0.6)';
      badge.className = 'pill pill-rose';
      badge.textContent = 'VERDICT: BLOCKED';
      triggerBlockedAlert();
    } else if (data.status === 'WAIVED') {
      box.style.backgroundColor = 'rgba(245, 158, 11, 0.2)';
      box.style.border = '1px solid rgba(245, 158, 11, 0.6)';
      badge.className = 'pill pill-amber';
      badge.textContent = 'VERDICT: WAIVED';
    } else {
      box.style.backgroundColor = 'rgba(16, 185, 129, 0.2)';
      box.style.border = '1px solid rgba(16, 185, 129, 0.6)';
      badge.className = 'pill pill-emerald';
      badge.textContent = 'VERDICT: ALLOWED';
    }

    await fetchDeviceData();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

function filterLogs(status) {
  state.logFilterStatus = status;
  document.querySelectorAll('#logs-filter-tabs .tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-status') === status);
  });
  renderLogsTable(state.logs);
}

function handleLogSearch(query) {
  state.logSearchQuery = query.trim();
  renderLogsTable(state.logs);
}

// ============================================================================
// DEVICE CREATION & LOGOUT
// ============================================================================

function openAddDeviceModal() {
  document.getElementById('new-device-name').value = '';
  document.getElementById('modal-add-device').classList.remove('hidden');
}

async function handleNewDeviceSubmit(e) {
  e.preventDefault();
  const name = document.getElementById('new-device-name').value.trim();
  try {
    const res = await fetch('/api/devices', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_name: name })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to create device');

    showToast(`Device "${data.device_name}" created with Identity Key ${data.pairing_key}`, 'success');
    closeModal('modal-add-device');
    state.currentDeviceId = data.id;
    await fetchDevicesList();
    await fetchDeviceData();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function handleLogout() {
  await fetch('/api/auth/logout', { method: 'POST' });
  window.location.href = '/login';
}

// ============================================================================
// SYSTEM BOOTSTRAP
// ============================================================================

document.addEventListener('DOMContentLoaded', async () => {
  startCountdownTicker();

  // Initial Sync
  await checkDatabaseHealth();
  await fetchDevicesList();
  await fetchDeviceData();

  // Periodic Overlap-Safe Polling (every 3 seconds)
  setInterval(async () => {
    await checkDatabaseHealth();
    await fetchDeviceData();
  }, 3000);
});
