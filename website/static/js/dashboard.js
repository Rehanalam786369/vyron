/**
 * VYRON Control Panel Dashboard
 * Rock-Solid Cyber-Telemetry Client Logic
 */

// Application State
const state = {
  rules: [],
  logs: [],
  stats: {},
  settings: {
    guided_mode: false,
    device_name: 'Android Handover Device',
  },
  activeRuleTab: 'all',
  ruleSearchQuery: '',
  activeLogFilter: 'ALL',
  logSearchQuery: '',
  lastBlockedLogId: null,
  isFetching: false,
  selectedDurationMins: '',
  pinAction: null, // 'toggle_mode' or 'clear_logs'
};

// Global Chart Instances
let trafficVerdictChart = null;
let rulesBreakdownChart = null;
let alertBannerTimeout = null;

// ============================================================================
// UTILITIES & ESCAPING
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

  const toast = document.createElement('div');
  toast.className = `toast-enter pointer-events-auto flex items-center justify-between p-3 rounded-xl border shadow-xl text-xs font-semibold backdrop-blur-md transition-all ${
    type === 'success'
      ? 'bg-emerald-950/90 border-emerald-500/60 text-emerald-200'
      : type === 'error'
      ? 'bg-rose-950/90 border-rose-500/60 text-rose-200'
      : 'bg-cyan-950/90 border-cyan-500/60 text-cyan-200'
  }`;

  const iconSvg =
    type === 'success'
      ? `<svg class="w-4 h-4 mr-2 text-emerald-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>`
      : type === 'error'
      ? `<svg class="w-4 h-4 mr-2 text-rose-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>`
      : `<svg class="w-4 h-4 mr-2 text-cyan-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>`;

  toast.innerHTML = `
    <div class="flex items-center">
      ${iconSvg}
      <span>${escapeHtml(message)}</span>
    </div>
    <button class="ml-3 text-slate-400 hover:text-white" onclick="this.parentElement.remove()">
      <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
    </button>
  `;

  stack.appendChild(toast);

  setTimeout(() => {
    toast.classList.remove('toast-enter');
    toast.classList.add('toast-exit');
    setTimeout(() => toast.remove(), 250);
  }, 3500);
}

function formatCountdown(totalSeconds) {
  if (totalSeconds <= 0) return 'Expired';
  const m = Math.floor(totalSeconds / 60);
  const s = totalSeconds % 60;
  if (m > 60) {
    const h = Math.floor(m / 60);
    const remM = m % 60;
    return `${h}h ${remM}m`;
  }
  return `${m}m ${s < 10 ? '0' : ''}${s}s`;
}

function formatIsoTime(isoStr) {
  if (!isoStr) return '';
  try {
    const date = new Date(isoStr);
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  } catch (e) {
    return isoStr;
  }
}

function triggerBlockedAlert() {
  const banner = document.getElementById('blocked-alert-banner');
  if (!banner) return;

  banner.classList.remove('hidden');
  if (alertBannerTimeout) {
    clearTimeout(alertBannerTimeout);
  }
  alertBannerTimeout = setTimeout(() => {
    banner.classList.add('hidden');
  }, 3500);
}

// ============================================================================
// CHARTS INITIALIZATION (ONCE ON STARTUP)
// ============================================================================

function initCharts() {
  // Chart 1: Traffic Verdict (Doughnut)
  const ctxTraffic = document.getElementById('trafficVerdictChart')?.getContext('2d');
  if (ctxTraffic) {
    trafficVerdictChart = new Chart(ctxTraffic, {
      type: 'doughnut',
      data: {
        labels: ['Allowed Traffic', 'Blocked Requests'],
        datasets: [
          {
            data: [0, 0],
            backgroundColor: ['#10b981', '#f43f5e'],
            borderColor: '#0a0e1a',
            borderWidth: 3,
            hoverOffset: 4,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '72%',
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              boxWidth: 12,
              padding: 14,
              color: '#94a3b8',
              font: { family: 'Plus Jakarta Sans', size: 11, weight: '500' },
            },
          },
          tooltip: {
            backgroundColor: '#0f172a',
            borderColor: '#334155',
            borderWidth: 1,
            titleFont: { family: 'JetBrains Mono', size: 12 },
            bodyFont: { family: 'Plus Jakarta Sans', size: 12 },
          },
        },
      },
    });
  }

  // Chart 2: Active Rules Breakdown (Bar)
  const ctxRules = document.getElementById('rulesBreakdownChart')?.getContext('2d');
  if (ctxRules) {
    rulesBreakdownChart = new Chart(ctxRules, {
      type: 'bar',
      data: {
        labels: ['DNS Domains', 'IP Addresses', 'Android Apps'],
        datasets: [
          {
            label: 'Active Rules',
            data: [0, 0, 0],
            backgroundColor: ['#06b6d4', '#a855f7', '#10b981'],
            borderRadius: 6,
            barThickness: 32,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: {
            grid: { display: false },
            ticks: {
              color: '#94a3b8',
              font: { family: 'Plus Jakarta Sans', size: 11, weight: '500' },
            },
          },
          y: {
            beginAtZero: true,
            ticks: {
              stepSize: 1,
              color: '#64748b',
              font: { family: 'JetBrains Mono', size: 10 },
            },
            grid: { color: 'rgba(51, 65, 85, 0.3)' },
          },
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#0f172a',
            borderColor: '#334155',
            borderWidth: 1,
            titleFont: { family: 'JetBrains Mono', size: 12 },
            bodyFont: { family: 'Plus Jakarta Sans', size: 12 },
          },
        },
      },
    });
  }
}

function updateCharts(stats) {
  if (trafficVerdictChart) {
    const allowed = stats.allowed_logs || 0;
    const blocked = stats.blocked_logs || 0;
    trafficVerdictChart.data.datasets[0].data = [allowed, blocked];
    trafficVerdictChart.update('none');
  }

  if (rulesBreakdownChart) {
    const domainCount = stats.rules_by_type?.domain || 0;
    const ipCount = stats.rules_by_type?.ip || 0;
    const appCount = stats.rules_by_type?.app || 0;
    rulesBreakdownChart.data.datasets[0].data = [domainCount, ipCount, appCount];
    rulesBreakdownChart.update('none');
  }
}

// ============================================================================
// DATA POLLING & SYNCHRONIZATION
// ============================================================================

async function checkDatabaseHealth() {
  try {
    const res = await fetch('/api/health');
    const data = await res.json();
    const pill = document.getElementById('db-health-pill');
    const dot = document.getElementById('db-health-dot');
    const text = document.getElementById('db-health-text');

    if (res.ok && data.status === 'ok') {
      state.dbConnected = true;
      if (pill) {
        pill.className = 'flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-medium border bg-emerald-950/60 border-emerald-500/50 text-emerald-400 ml-2';
      }
      if (dot) {
        dot.className = 'w-2 h-2 rounded-full bg-emerald-400 pulse-indicator';
      }
      if (text) text.textContent = 'DB: CONNECTED';
    } else {
      state.dbConnected = false;
      if (pill) {
        pill.className = 'flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-medium border bg-rose-950/60 border-rose-500/50 text-rose-400 ml-2';
      }
      if (dot) {
        dot.className = 'w-2 h-2 rounded-full bg-rose-500 pulse-indicator';
      }
      if (text) text.textContent = 'DB: ERROR';
    }
  } catch (err) {
    state.dbConnected = false;
    const pill = document.getElementById('db-health-pill');
    const dot = document.getElementById('db-health-dot');
    const text = document.getElementById('db-health-text');
    if (pill) {
      pill.className = 'flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-medium border bg-rose-950/60 border-rose-500/50 text-rose-400 ml-2';
    }
    if (dot) dot.className = 'w-2 h-2 rounded-full bg-rose-500 pulse-indicator';
    if (text) text.textContent = 'DB: DISCONNECTED';
  }
}

async function fetchDashboardData() {
  if (state.isFetching) return;
  state.isFetching = true;

  try {
    const res = await fetch('/api/dashboard');
    if (!res.ok) {
      throw new Error(`Server returned ${res.status}`);
    }
    const data = await res.json();

    // Check for newly detected blocked connection from polling
    if (data.logs && data.logs.length > 0) {
      const topBlocked = data.logs.find(l => l.status === 'BLOCKED');
      if (topBlocked) {
        if (state.lastBlockedLogId !== null && topBlocked.id > state.lastBlockedLogId) {
          triggerBlockedAlert();
        }
        state.lastBlockedLogId = topBlocked.id;
      }
    }

    state.rules = data.rules || [];
    state.logs = data.logs || [];
    state.stats = data.stats || {};
    state.settings = data.settings || state.settings;

    renderKPIs(state.stats, state.settings);
    renderSettings(state.settings);
    updateCharts(state.stats);
    renderRules();
    renderLogs();
    updateTabCounts();
  } catch (err) {
    console.warn('Dashboard poll error:', err);
  } finally {
    state.isFetching = false;
  }
}

// ============================================================================
// RENDERING FUNCTIONS
// ============================================================================

function renderKPIs(stats, settings) {
  const elTotal = document.getElementById('stat-total-logs');
  const elAllowed = document.getElementById('stat-allowed-logs');
  const elBlocked = document.getElementById('stat-blocked-logs');
  const elBlockRate = document.getElementById('stat-block-rate');
  const elActiveRules = document.getElementById('stat-active-rules');
  const elTotalRules = document.getElementById('stat-total-rules');
  const elRulesBreakdown = document.getElementById('stat-rules-types-sub');

  if (elTotal) elTotal.textContent = stats.total_logs ?? 0;
  if (elAllowed) elAllowed.textContent = stats.allowed_logs ?? 0;
  if (elBlocked) elBlocked.textContent = stats.blocked_logs ?? 0;
  if (elBlockRate) elBlockRate.textContent = `${stats.block_rate_percent ?? 0}% Rate`;
  if (elActiveRules) elActiveRules.textContent = stats.active_rules_count ?? 0;
  if (elTotalRules) elTotalRules.textContent = stats.total_rules_count ?? 0;

  if (elRulesBreakdown && stats.rules_by_type) {
    const d = stats.rules_by_type.domain ?? 0;
    const ip = stats.rules_by_type.ip ?? 0;
    const a = stats.rules_by_type.app ?? 0;
    elRulesBreakdown.textContent = `${d}D · ${ip}IP · ${a}A`;
  }
}

function renderSettings(settings) {
  const isGuided = !!settings.guided_mode;
  const devName = settings.device_name || 'Android Handover Device';

  // Device Name indicators
  const navDev = document.getElementById('nav-device-name');
  const statDev = document.getElementById('stat-device-name');
  if (navDev) navDev.textContent = devName;
  if (statDev) statDev.textContent = devName;

  // Guided Mode Badges & Buttons
  const badge = document.getElementById('guided-mode-badge');
  const text = document.getElementById('guided-mode-text');
  const icon = document.getElementById('guided-mode-icon');
  const lockBtn = document.getElementById('btn-toggle-lock');
  const lockBtnText = document.getElementById('lock-btn-text');

  const cardStatusTitle = document.getElementById('handover-status-title');
  const cardPill = document.getElementById('handover-pill');
  const cardIcon = document.getElementById('handover-status-icon');

  if (isGuided) {
    if (badge) {
      badge.className = 'flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all bg-emerald-950/80 text-emerald-400 border-emerald-500/50 shadow-sm shadow-emerald-500/20';
    }
    if (text) text.textContent = 'GUIDED MODE: LOCKED';
    if (icon) {
      icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>';
    }
    if (lockBtn) {
      lockBtn.className = 'px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white shadow-sm shadow-rose-600/30 transition flex items-center space-x-1';
    }
    if (lockBtnText) lockBtnText.textContent = 'Unlock Handover';

    if (cardStatusTitle) {
      cardStatusTitle.textContent = 'Protected';
      cardStatusTitle.className = 'text-2xl font-bold font-mono tracking-tight text-emerald-400';
    }
    if (cardPill) {
      cardPill.textContent = 'LOCKED';
      cardPill.className = 'text-xs px-2 py-0.5 rounded-full font-mono font-bold bg-emerald-950 border border-emerald-500/60 text-emerald-400';
    }
    if (cardIcon) {
      cardIcon.className = 'w-8 h-8 rounded-lg bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400';
    }
  } else {
    if (badge) {
      badge.className = 'flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all bg-slate-800/80 text-slate-400 border-slate-700';
    }
    if (text) text.textContent = 'GUIDED MODE: OFF';
    if (icon) {
      icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z"/>';
    }
    if (lockBtn) {
      lockBtn.className = 'px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white shadow-sm shadow-cyan-600/30 transition flex items-center space-x-1';
    }
    if (lockBtnText) lockBtnText.textContent = 'Lock Handover';

    if (cardStatusTitle) {
      cardStatusTitle.textContent = 'Standby';
      cardStatusTitle.className = 'text-2xl font-bold font-mono tracking-tight text-slate-300';
    }
    if (cardPill) {
      cardPill.textContent = 'UNLOCKED';
      cardPill.className = 'text-xs px-2 py-0.5 rounded-full font-mono font-medium bg-slate-800 border border-slate-700 text-slate-400';
    }
    if (cardIcon) {
      cardIcon.className = 'w-8 h-8 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-400';
    }
  }
}

function updateTabCounts() {
  const counts = {
    all: state.rules.length,
    domain: 0,
    ip: 0,
    app: 0,
    timed: 0,
  };

  state.rules.forEach(r => {
    if (r.rule_type in counts) counts[r.rule_type]++;
    if (r.expires_at) counts.timed++;
  });

  const elAll = document.getElementById('tab-count-all');
  const elDom = document.getElementById('tab-count-domain');
  const elIp = document.getElementById('tab-count-ip');
  const elApp = document.getElementById('tab-count-app');
  const elTimed = document.getElementById('tab-count-timed');

  if (elAll) elAll.textContent = counts.all;
  if (elDom) elDom.textContent = counts.domain;
  if (elIp) elIp.textContent = counts.ip;
  if (elApp) elApp.textContent = counts.app;
  if (elTimed) elTimed.textContent = counts.timed;
}

function renderRules() {
  const container = document.getElementById('rules-list-container');
  if (!container) return;

  const tab = state.activeRuleTab;
  const q = state.ruleSearchQuery.toLowerCase();

  const filtered = state.rules.filter(r => {
    if (tab === 'timed' && !r.expires_at) return false;
    if (tab !== 'all' && tab !== 'timed' && r.rule_type !== tab) return false;
    if (q) {
      const matchTarget = r.target.toLowerCase().includes(q);
      const matchNote = (r.note || '').toLowerCase().includes(q);
      if (!matchTarget && !matchNote) return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    container.innerHTML = `
      <div class="py-12 text-center text-slate-500 text-xs font-mono">
        No active rules found matching current criteria.
      </div>
    `;
    return;
  }

  let html = '';
  filtered.forEach(r => {
    const isBlock = r.action === 'BLOCK';
    const actionBadge = isBlock
      ? '<span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-rose-950/80 text-rose-400 border border-rose-800/60">BLOCK</span>'
      : '<span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-emerald-950/80 text-emerald-400 border border-emerald-800/60">ALLOW</span>';

    const typeBadge = `<span class="px-1.5 py-0.5 rounded text-[10px] font-mono uppercase bg-slate-800 text-slate-400 border border-slate-700">${escapeHtml(r.rule_type)}</span>`;

    let countdownBadge = '';
    if (r.expires_at) {
      const sec = r.remaining_seconds ?? 0;
      countdownBadge = `
        <span class="rule-countdown-pill flex items-center space-x-1 text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950/60 border border-amber-600/40 text-amber-300" data-rule-id="${r.id}">
          <svg class="w-3 h-3 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
          <span class="countdown-text">${formatCountdown(sec)}</span>
        </span>
      `;
    }

    const checkedAttr = r.is_active ? 'checked' : '';

    html += `
      <div class="cyber-card p-3 rounded-lg border border-slate-800 hover:border-slate-700 transition flex items-center justify-between gap-3">
        <div class="flex items-center space-x-2.5 min-w-0">
          <div class="flex-shrink-0">${actionBadge}</div>
          <div class="flex-shrink-0">${typeBadge}</div>
          <div class="min-w-0">
            <div class="text-xs font-mono font-medium text-slate-200 truncate" title="${escapeHtml(r.target)}">
              ${escapeHtml(r.target)}
            </div>
            ${
              r.note
                ? `<div class="text-[11px] text-slate-400 truncate max-w-xs sm:max-w-md">${escapeHtml(r.note)}</div>`
                : ''
            }
          </div>
        </div>

        <div class="flex items-center space-x-3 flex-shrink-0">
          ${countdownBadge}
          
          <!-- Toggle Switch -->
          <label class="relative inline-flex items-center cursor-pointer" title="Toggle active/pause">
            <input type="checkbox" class="sr-only toggle-rule-checkbox" data-id="${r.id}" ${checkedAttr}>
            <div class="w-8 h-4 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-slate-400 peer-checked:after:bg-white after:border-slate-600 after:border after:rounded-full after:h-3 after:w-3 after:transition-all peer-checked:bg-emerald-600"></div>
          </label>

          <!-- Delete Rule Button -->
          <button class="btn-delete-rule text-slate-500 hover:text-rose-400 p-1 rounded hover:bg-rose-950/40 transition" data-id="${r.id}" title="Delete rule">
            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
            </svg>
          </button>
        </div>
      </div>
    `;
  });

  container.innerHTML = html;
}

function renderLogs() {
  const container = document.getElementById('logs-container');
  if (!container) return;

  const filter = state.activeLogFilter;
  const q = state.logSearchQuery.toLowerCase();

  const filtered = state.logs.filter(l => {
    if (filter !== 'ALL' && l.status !== filter) return false;
    if (q) {
      const matchTarget = l.target.toLowerCase().includes(q);
      const matchReason = (l.reason || '').toLowerCase().includes(q);
      const matchDev = (l.device_name || '').toLowerCase().includes(q);
      if (!matchTarget && !matchReason && !matchDev) return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    container.innerHTML = `
      <div class="py-12 text-center text-slate-500 text-xs">
        No network logs found.
      </div>
    `;
    return;
  }

  let html = '';
  filtered.forEach(l => {
    const isBlock = l.status === 'BLOCKED';
    const statusClass = isBlock ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold';
    const rowBorder = isBlock ? 'border-rose-950/40 hover:border-rose-800/40' : 'border-slate-800 hover:border-slate-700';

    const sourceBadge =
      l.source === 'ANDROID_VPN'
        ? '<span class="text-[9px] px-1.5 py-0.2 rounded bg-indigo-950 text-indigo-300 border border-indigo-800/60 font-mono">VPN</span>'
        : '<span class="text-[9px] px-1.5 py-0.2 rounded bg-purple-950 text-purple-300 border border-purple-800/60 font-mono">SIM</span>';

    const typeBadge = `<span class="text-[9px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 uppercase font-mono">${escapeHtml(l.rule_type)}</span>`;

    html += `
      <div class="p-2.5 rounded-lg border ${rowBorder} bg-cyber-900/40 text-xs transition space-y-1">
        <div class="flex items-center justify-between text-[11px]">
          <div class="flex items-center space-x-1.5">
            <span class="text-slate-500">${formatIsoTime(l.created_at)}</span>
            ${sourceBadge}
            ${typeBadge}
          </div>
          <span class="${statusClass}">${escapeHtml(l.status)}</span>
        </div>
        <div class="text-slate-200 font-mono font-medium break-all">
          ${escapeHtml(l.target)}
        </div>
        <div class="text-[11px] text-slate-400 truncate">
          ${escapeHtml(l.reason)}
        </div>
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
    let expiredDetected = false;

    state.rules.forEach(r => {
      if (r.remaining_seconds !== null && r.remaining_seconds !== undefined) {
        r.remaining_seconds = Math.max(0, r.remaining_seconds - 1);
        if (r.remaining_seconds === 0) {
          expiredDetected = true;
        }
      }
    });

    // Update pills in DOM
    const countdownPills = document.querySelectorAll('.rule-countdown-pill');
    countdownPills.forEach(pill => {
      const id = parseInt(pill.getAttribute('data-rule-id'), 10);
      const rule = state.rules.find(r => r.id === id);
      if (rule && rule.remaining_seconds !== null) {
        const span = pill.querySelector('.countdown-text');
        if (span) {
          span.textContent = formatCountdown(rule.remaining_seconds);
        }
      }
    });

    // If an expired rule hit zero, trigger backend purge & sync
    if (expiredDetected) {
      fetchDashboardData();
    }
  }, 1000);
}

// ============================================================================
// EVENT HANDLERS & MODAL MANAGEMENT
// ============================================================================

function setupEventListeners() {
  // 1. Dynamic Rule Type Placeholder & Hint
  const typeSelect = document.getElementById('rule-type-select');
  const targetInput = document.getElementById('rule-target-input');
  const targetHint = document.getElementById('rule-target-hint');

  if (typeSelect && targetInput && targetHint) {
    typeSelect.addEventListener('change', () => {
      const val = typeSelect.value;
      if (val === 'domain') {
        targetInput.placeholder = 'e.g. instagram.com or reels.instagram.com';
        targetHint.innerHTML = 'Domains match exact & subdomains. URLs like <code class="text-cyan-400">https://m.instagram.com/reels</code> are automatically normalized.';
      } else if (val === 'ip') {
        targetInput.placeholder = 'e.g. 157.240.22.174 or 1.1.1.1';
        targetHint.innerHTML = 'Valid IPv4 or IPv6 network address for strict direct packet drop.';
      } else if (val === 'app') {
        targetInput.placeholder = 'e.g. com.dts.freefireth or com.instagram.android';
        targetHint.innerHTML = 'Android application package identifier (reverse-DNS format).';
      }
    });
  }

  // 2. Duration Preset Chips
  const presetChips = document.querySelectorAll('.preset-chip');
  const customDurationInput = document.getElementById('rule-duration-custom');
  const durationDisplay = document.getElementById('duration-display');

  presetChips.forEach(chip => {
    chip.addEventListener('click', () => {
      presetChips.forEach(c => {
        c.className = 'preset-chip px-2.5 py-1 text-xs font-mono rounded bg-cyber-850 text-slate-300 border border-slate-700 hover:border-slate-500';
      });
      chip.className = 'preset-chip active px-2.5 py-1 text-xs font-mono rounded bg-cyan-600 text-white border border-cyan-500';

      const mins = chip.getAttribute('data-mins');
      state.selectedDurationMins = mins;
      if (customDurationInput) customDurationInput.value = '';

      if (durationDisplay) {
        durationDisplay.textContent = mins ? `Temporary: ${mins} minute(s)` : 'Permanent Policy';
      }
    });
  });

  if (customDurationInput) {
    customDurationInput.addEventListener('input', () => {
      const val = customDurationInput.value.trim();
      presetChips.forEach(c => {
        c.className = 'preset-chip px-2.5 py-1 text-xs font-mono rounded bg-cyber-850 text-slate-300 border border-slate-700 hover:border-slate-500';
      });
      state.selectedDurationMins = val;
      if (durationDisplay) {
        durationDisplay.textContent = val ? `Temporary: ${val} minute(s)` : 'Permanent Policy';
      }
    });
  }

  // 3. Add Rule Form Submit
  const formAddRule = document.getElementById('form-add-rule');
  if (formAddRule) {
    formAddRule.addEventListener('submit', async e => {
      e.preventDefault();
      const ruleType = document.getElementById('rule-type-select').value;
      const action = document.getElementById('rule-action-select').value;
      const target = document.getElementById('rule-target-input').value.trim();
      const note = document.getElementById('rule-note-input').value.trim();
      const durationMins = state.selectedDurationMins ? parseInt(state.selectedDurationMins, 10) : null;

      try {
        const res = await fetch('/api/rules', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            rule_type: ruleType,
            action: action,
            target: target,
            note: note,
            duration_mins: durationMins,
          }),
        });

        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.error || 'Failed to deploy rule');
        }

        showToast(`Rule deployed for ${data.target}`, 'success');
        document.getElementById('rule-target-input').value = '';
        document.getElementById('rule-note-input').value = '';

        await fetchDashboardData();
      } catch (err) {
        showToast(err.message, 'error');
      }
    });
  }

  // 4. Rule Tabs
  const ruleTabs = document.querySelectorAll('.rule-tab');
  ruleTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      ruleTabs.forEach(t => {
        t.className = 'rule-tab px-3 py-1.5 text-xs font-semibold rounded-lg text-slate-400 hover:text-white hover:bg-cyber-800 border border-transparent';
      });
      tab.className = 'rule-tab active px-3 py-1.5 text-xs font-semibold rounded-lg bg-cyber-800 text-white border border-cyan-500/50';
      state.activeRuleTab = tab.getAttribute('data-tab');
      renderRules();
    });
  });

  // 5. Search Rules Input
  const searchRulesInput = document.getElementById('search-rules-input');
  if (searchRulesInput) {
    searchRulesInput.addEventListener('input', e => {
      state.ruleSearchQuery = e.target.value.trim();
      renderRules();
    });
  }

  // 6. Rules Container Click Delegation (Toggle & Delete)
  const rulesListContainer = document.getElementById('rules-list-container');
  if (rulesListContainer) {
    rulesListContainer.addEventListener('change', async e => {
      if (e.target.classList.contains('toggle-rule-checkbox')) {
        const id = e.target.getAttribute('data-id');
        try {
          const res = await fetch(`/api/rules/${id}/toggle`, { method: 'PATCH' });
          const data = await res.json();
          if (!res.ok) throw new Error(data.error || 'Failed to toggle rule');
          showToast(`Rule #${id} is now ${data.is_active ? 'Active' : 'Paused'}`, 'info');
          await fetchDashboardData();
        } catch (err) {
          showToast(err.message, 'error');
          e.target.checked = !e.target.checked;
        }
      }
    });

    rulesListContainer.addEventListener('click', async e => {
      const delBtn = e.target.closest('.btn-delete-rule');
      if (delBtn) {
        const id = delBtn.getAttribute('data-id');
        if (!confirm(`Are you sure you want to permanently delete rule #${id}?`)) {
          return;
        }
        try {
          const res = await fetch(`/api/rules/${id}`, { method: 'DELETE' });
          const data = await res.json();
          if (!res.ok) throw new Error(data.error || 'Failed to delete rule');
          showToast(`Rule #${id} deleted`, 'success');
          await fetchDashboardData();
        } catch (err) {
          showToast(err.message, 'error');
        }
      }
    });
  }

  // 7. Interactive Traffic Simulator
  const formSimulate = document.getElementById('form-simulate');
  if (formSimulate) {
    formSimulate.addEventListener('submit', async e => {
      e.preventDefault();
      const ruleType = document.getElementById('sim-type-select').value;
      const target = document.getElementById('sim-target-input').value.trim();

      try {
        const res = await fetch('/api/simulate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ rule_type: ruleType, target: target }),
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Simulation failed');

        // Render verdict banner
        const verdictCard = document.getElementById('sim-verdict-card');
        const verdictStatus = document.getElementById('sim-verdict-status');
        const verdictTime = document.getElementById('sim-verdict-time');
        const verdictTarget = document.getElementById('sim-verdict-target');
        const verdictReason = document.getElementById('sim-verdict-reason');

        if (verdictCard) {
          verdictCard.classList.remove('hidden');
          const isBlock = data.status === 'BLOCKED';
          verdictCard.className = isBlock
            ? 'mt-4 p-3 rounded-lg border bg-rose-950/70 border-rose-500/70 cyber-glow-rose'
            : 'mt-4 p-3 rounded-lg border bg-emerald-950/70 border-emerald-500/70 cyber-glow-emerald';

          if (verdictStatus) {
            verdictStatus.textContent = isBlock ? 'VERDICT: BLOCKED' : 'VERDICT: ALLOWED';
            verdictStatus.className = isBlock ? 'text-xs font-bold font-mono text-rose-400' : 'text-xs font-bold font-mono text-emerald-400';
          }
          if (verdictTime) verdictTime.textContent = 'JUST NOW';
          if (verdictTarget) verdictTarget.textContent = data.target;
          if (verdictReason) verdictReason.textContent = data.reason;

          if (isBlock) {
            triggerBlockedAlert();
          }
        }

        await fetchDashboardData();
      } catch (err) {
        showToast(err.message, 'error');
      }
    });
  }

  // 8. Simulator Preset Chips
  const simChips = document.querySelectorAll('.sim-chip');
  simChips.forEach(chip => {
    chip.addEventListener('click', () => {
      const type = chip.getAttribute('data-type');
      const val = chip.getAttribute('data-val');

      const simType = document.getElementById('sim-type-select');
      const simTarget = document.getElementById('sim-target-input');

      if (simType) simType.value = type;
      if (simTarget) simTarget.value = val;

      // Auto trigger simulation
      formSimulate?.dispatchEvent(new Event('submit'));
    });
  });

  // 9. Log Filters
  const logFilterBtns = document.querySelectorAll('.log-filter-btn');
  logFilterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      logFilterBtns.forEach(b => {
        b.className = 'log-filter-btn px-2.5 py-1 text-xs font-mono rounded text-slate-400 hover:text-white border border-transparent';
      });
      btn.className = 'log-filter-btn active px-2.5 py-1 text-xs font-mono rounded bg-cyber-800 text-white border border-slate-600';
      state.activeLogFilter = btn.getAttribute('data-status');
      renderLogs();
    });
  });

  // 10. Search Logs Input
  const searchLogsInput = document.getElementById('search-logs-input');
  if (searchLogsInput) {
    searchLogsInput.addEventListener('input', e => {
      state.logSearchQuery = e.target.value.trim();
      renderLogs();
    });
  }

  // 11. Clear Logs Button
  const btnClearLogs = document.getElementById('btn-clear-logs');
  if (btnClearLogs) {
    btnClearLogs.addEventListener('click', () => {
      if (state.settings.guided_mode) {
        // Must prompt for PIN
        openPinModal('clear_logs', 'Supervisor Authentication Required', 'Guided Mode is active. Enter Supervisor PIN to purge network telemetry.');
      } else {
        if (confirm('Are you sure you want to clear all network telemetry logs?')) {
          executeClearLogs('');
        }
      }
    });
  }

  // 12. Toggle Handover Lock (Guided Mode)
  const btnToggleLock = document.getElementById('btn-toggle-lock');
  if (btnToggleLock) {
    btnToggleLock.addEventListener('click', () => {
      const targetState = !state.settings.guided_mode;
      const title = targetState ? 'Enable Guided Handover' : 'Disable Guided Handover';
      const desc = targetState
        ? 'Lock network control panel and enforce policy sync on bound Android device.'
        : 'Unlock control panel using Supervisor PIN.';
      openPinModal('toggle_mode', title, desc);
    });
  }

  // 13. Supervisor PIN Modal Actions
  const btnCancelPin = document.getElementById('btn-cancel-pin-modal');
  const btnConfirmPin = document.getElementById('btn-confirm-pin');
  const modalPin = document.getElementById('modal-pin');
  const inputPin = document.getElementById('input-supervisor-pin');

  if (btnCancelPin) btnCancelPin.addEventListener('click', closePinModal);
  if (modalPin) {
    modalPin.addEventListener('click', e => {
      if (e.target === modalPin) closePinModal();
    });
  }

  if (btnConfirmPin && inputPin) {
    const submitPinAction = async () => {
      const pin = inputPin.value.trim();
      if (!pin) {
        showPinError('PIN is required.');
        return;
      }

      if (state.pinAction === 'toggle_mode') {
        const targetState = !state.settings.guided_mode;
        try {
          const res = await fetch('/api/settings/guided-mode', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: targetState, pin: pin }),
          });

          const data = await res.json();
          if (!res.ok) throw new Error(data.error || 'Authentication failed');

          showToast(
            `Guided Mode ${data.guided_mode ? 'LOCKED' : 'UNLOCKED'} successfully`,
            'success'
          );
          closePinModal();
          await fetchDashboardData();
        } catch (err) {
          showPinError(err.message);
        }
      } else if (state.pinAction === 'clear_logs') {
        executeClearLogs(pin);
      }
    };

    btnConfirmPin.addEventListener('click', submitPinAction);
    inputPin.addEventListener('keydown', e => {
      if (e.key === 'Enter') submitPinAction();
    });
  }

  // 14. Change PIN Modal
  const btnOpenPinModal = document.getElementById('btn-open-pin-modal');
  const modalChangePin = document.getElementById('modal-change-pin');
  const btnCancelChangePin = document.getElementById('btn-cancel-change-pin');
  const formChangePin = document.getElementById('form-change-pin');

  if (btnOpenPinModal && modalChangePin) {
    btnOpenPinModal.addEventListener('click', () => {
      modalChangePin.classList.remove('hidden');
      document.getElementById('input-current-pin')?.focus();
    });
  }
  if (btnCancelChangePin && modalChangePin) {
    btnCancelChangePin.addEventListener('click', () => modalChangePin.classList.add('hidden'));
  }
  if (modalChangePin) {
    modalChangePin.addEventListener('click', e => {
      if (e.target === modalChangePin) modalChangePin.classList.add('hidden');
    });
  }

  if (formChangePin) {
    formChangePin.addEventListener('submit', async e => {
      e.preventDefault();
      const curPin = document.getElementById('input-current-pin').value.trim();
      const newPin = document.getElementById('input-new-pin').value.trim();
      const confirmPin = document.getElementById('input-confirm-new-pin').value.trim();
      const errBox = document.getElementById('change-pin-error');

      if (newPin !== confirmPin) {
        if (errBox) {
          errBox.textContent = 'New PIN and Confirmation PIN do not match.';
          errBox.classList.remove('hidden');
        }
        return;
      }

      if (!/^\d{4,8}$/.test(newPin)) {
        if (errBox) {
          errBox.textContent = 'New PIN must be 4 to 8 numeric digits.';
          errBox.classList.remove('hidden');
        }
        return;
      }

      try {
        const res = await fetch('/api/settings/pin', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ current_pin: curPin, new_pin: newPin }),
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed to update PIN');

        showToast('Supervisor PIN updated successfully', 'success');
        modalChangePin.classList.add('hidden');
        formChangePin.reset();
        if (errBox) errBox.classList.add('hidden');
      } catch (err) {
        if (errBox) {
          errBox.textContent = err.message;
          errBox.classList.remove('hidden');
        }
      }
    });
  }

  // 15. Edit Device Name Modal
  const btnEditDev = document.getElementById('btn-edit-device');
  const modalDev = document.getElementById('modal-device');
  const btnCancelDev = document.getElementById('btn-cancel-device-modal');
  const formEditDev = document.getElementById('form-edit-device');
  const inputDev = document.getElementById('input-device-name');

  if (btnEditDev && modalDev && inputDev) {
    btnEditDev.addEventListener('click', () => {
      inputDev.value = state.settings.device_name || 'Android Handover Device';
      modalDev.classList.remove('hidden');
      inputDev.focus();
    });
  }
  if (btnCancelDev && modalDev) {
    btnCancelDev.addEventListener('click', () => modalDev.classList.add('hidden'));
  }
  if (modalDev) {
    modalDev.addEventListener('click', e => {
      if (e.target === modalDev) modalDev.classList.add('hidden');
    });
  }

  if (formEditDev && inputDev) {
    formEditDev.addEventListener('submit', async e => {
      e.preventDefault();
      const newName = inputDev.value.trim();
      if (!newName) return;

      try {
        const res = await fetch('/api/settings/device', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ device_name: newName }),
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed to update device');

        showToast(`Target device renamed to "${data.device_name}"`, 'success');
        modalDev.classList.add('hidden');
        state.settings.device_name = data.device_name;
        renderSettings(state.settings);
      } catch (err) {
        showToast(err.message, 'error');
      }
    });
  }

  // Global Escape key to dismiss modals
  window.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      closePinModal();
      modalChangePin?.classList.add('hidden');
      modalDev?.classList.add('hidden');
    }
  });
}

function openPinModal(action, title, desc) {
  state.pinAction = action;
  const modal = document.getElementById('modal-pin');
  const titleEl = document.getElementById('modal-pin-title');
  const descEl = document.getElementById('modal-pin-desc');
  const input = document.getElementById('input-supervisor-pin');
  const err = document.getElementById('pin-error-msg');

  if (titleEl) titleEl.textContent = title;
  if (descEl) descEl.textContent = desc;
  if (err) err.classList.add('hidden');
  if (input) {
    input.value = '';
    setTimeout(() => input.focus(), 50);
  }
  if (modal) modal.classList.remove('hidden');
}

function closePinModal() {
  const modal = document.getElementById('modal-pin');
  if (modal) modal.classList.add('hidden');
  const input = document.getElementById('input-supervisor-pin');
  if (input) input.value = '';
  const err = document.getElementById('pin-error-msg');
  if (err) err.classList.add('hidden');
  state.pinAction = null;
}

function showPinError(msg) {
  const err = document.getElementById('pin-error-msg');
  if (err) {
    err.textContent = msg;
    err.classList.remove('hidden');
  }
}

async function executeClearLogs(pin) {
  try {
    const res = await fetch('/api/logs', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pin: pin }),
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to clear logs');

    showToast('Network telemetry logs cleared', 'success');
    closePinModal();
    await fetchDashboardData();
  } catch (err) {
    if (state.pinAction === 'clear_logs') {
      showPinError(err.message);
    } else {
      showToast(err.message, 'error');
    }
  }
}

// ============================================================================
// SYSTEM BOOTSTRAP
// ============================================================================

document.addEventListener('DOMContentLoaded', async () => {
  initCharts();
  setupEventListeners();
  startCountdownTicker();

  // Initial sync
  await checkDatabaseHealth();
  await fetchDashboardData();

  // Overlap-safe periodic polling
  setInterval(async () => {
    await checkDatabaseHealth();
    await fetchDashboardData();
  }, 3000);
});
