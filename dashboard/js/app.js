/**
 * ARAN SOC Dashboard — Application entry point.
 * Handles routing, navigation, modal, ingest form, and auto-refresh.
 */
import { api } from './api.js';
import { showToast } from './notifications.js';
import { renderDashboard }  from './pages/dashboard.js';
import { renderEvents }     from './pages/events.js';
import { renderThreats }    from './pages/threats.js';
import { renderIncidents }  from './pages/incidents.js';
import { renderRisk }       from './pages/risk.js';
import { renderMonitoring } from './pages/monitoring.js';
import { renderMLAnalyzer } from './pages/ml-analyzer.js';
import { renderReports }    from './pages/reports.js';
import { renderSystem }     from './pages/system.js';

// ── State ─────────────────────────────────────────────────────
let currentPage = 'dashboard';
let currentPageCtrl = null;     // { refresh, destroy? }
let autoRefreshTimer = null;
let apiOnline = false;

const PAGE_TITLES = {
  dashboard:  'Dashboard',
  events:     'Security Events',
  threats:    'Threat Findings',
  incidents:  'Incident Management',
  risk:       'Risk Analysis',
  monitoring: 'Live Monitor',
  'ml-analyzer': 'ML Log Analyzer',
  reports:    'Reports',
  system:     'System Health',
};

const PAGE_RENDERERS = {
  dashboard:  renderDashboard,
  events:     renderEvents,
  threats:    renderThreats,
  incidents:  renderIncidents,
  risk:       renderRisk,
  monitoring: renderMonitoring,
  'ml-analyzer': renderMLAnalyzer,
  reports:    renderReports,
  system:     renderSystem,
};

// ── Navigation ────────────────────────────────────────────────
async function navigate(page) {
  if (!PAGE_RENDERERS[page]) return;

  // Destroy previous page's intervals
  if (currentPageCtrl?.destroy) currentPageCtrl.destroy();
  clearAutoRefresh();

  currentPage = page;

  // Update nav active state
  document.querySelectorAll('.nav-item').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.page === page);
  });

  // Update page title
  const titleEl = document.getElementById('page-title');
  if (titleEl) titleEl.textContent = PAGE_TITLES[page] || page;

  // Render page
  const content = document.getElementById('content');
  if (!content) return;
  content.innerHTML = `<div class="loading-row" style="padding:40px"><span class="spinner"></span></div>`;

  try {
    currentPageCtrl = await PAGE_RENDERERS[page](content);
  } catch (e) {
    content.innerHTML = `<div class="card" style="padding:24px;color:var(--red)">Failed to render page: ${e.message}</div>`;
  }

  // Auto-refresh for non-monitoring pages (monitoring has its own poll)
  if (page !== 'monitoring') {
    autoRefreshTimer = setInterval(() => {
      if (currentPageCtrl?.refresh) currentPageCtrl.refresh();
      checkApiStatus();
    }, 5000);
  }
}

function clearAutoRefresh() {
  if (autoRefreshTimer) { clearInterval(autoRefreshTimer); autoRefreshTimer = null; }
}

// ── API Status Indicator ──────────────────────────────────────
async function checkApiStatus() {
  try {
    const h = await api.health();
    apiOnline = true;

    const statusEl = document.getElementById('backend-status');
    if (statusEl) {
      statusEl.textContent = 'API Online';
      statusEl.className = 'system-tag';
    }

    // Update sidebar dots
    const apiDot = document.getElementById('api-dot');
    if (apiDot) { apiDot.className = 'dot'; }

    const monDot = document.getElementById('monitor-dot');
    if (monDot) {
      monDot.className = h.monitoring ? 'dot' : 'dot warning';
    }
  } catch (e) {
    apiOnline = false;
    const statusEl = document.getElementById('backend-status');
    if (statusEl) {
      statusEl.textContent = 'Backend Offline';
      statusEl.className = 'system-tag error';
    }
    const apiDot = document.getElementById('api-dot');
    if (apiDot) apiDot.className = 'dot danger';
  }
}

// ── Modal ─────────────────────────────────────────────────────
function openModal(id) {
  const m = document.getElementById(id);
  if (m) { m.classList.add('open'); m.setAttribute('aria-hidden', 'false'); }
}

function closeModal(id) {
  const m = document.getElementById(id);
  if (m) { m.classList.remove('open'); m.setAttribute('aria-hidden', 'true'); }
}

function bindModals() {
  document.getElementById('open-ingest-modal')?.addEventListener('click', () => openModal('ingest-modal'));

  document.querySelectorAll('.close-modal').forEach(btn => {
    btn.addEventListener('click', () => closeModal(btn.dataset.modal));
  });

  // Close on backdrop click
  document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) closeModal(modal.id);
    });
  });
}

// ── Ingest Form ───────────────────────────────────────────────
function bindIngestForm() {
  const form = document.getElementById('ingest-form');
  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const submit = document.getElementById('ingest-submit');
    submit.disabled = true;
    submit.textContent = '⏳ Submitting…';

    const payload = {
      username:  form.username.value.trim(),
      eventType: form.eventType.value,
      ipAddress: form.ipAddress.value.trim() || 'unknown',
      details:   form.details.value.trim(),
    };

    if (!payload.username || !payload.eventType) {
      showToast('Username and Event Type are required.', 'error');
      submit.disabled = false; submit.textContent = 'Submit Event';
      return;
    }

    try {
      const result = await api.ingestEvent(payload);
      form.reset();
      closeModal('ingest-modal');
      showToast(`Event accepted: [${result.eventType}] severity=${result.severity}`, 'success');
      // Refresh current page
      if (currentPageCtrl?.refresh) await currentPageCtrl.refresh();
    } catch (err) {
      showToast('Ingest failed: ' + err.message, 'error');
    } finally {
      submit.disabled = false; submit.textContent = 'Submit Event';
    }
  });
}

// ── Sidebar Toggle (mobile) ───────────────────────────────────
function bindSidebarToggle() {
  const toggleBtn = document.getElementById('sidebar-toggle');
  const sidebar   = document.getElementById('sidebar');
  if (!toggleBtn || !sidebar) return;

  toggleBtn.addEventListener('click', () => {
    sidebar.classList.toggle('open');
  });

  // Close sidebar when nav item clicked on mobile
  document.querySelectorAll('.nav-item').forEach(btn => {
    btn.addEventListener('click', () => {
      if (window.innerWidth <= 880) sidebar.classList.remove('open');
    });
  });
}

// ── Bootstrap ─────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  // Wire nav buttons
  document.querySelectorAll('.nav-item[data-page]').forEach(btn => {
    btn.addEventListener('click', () => navigate(btn.dataset.page));
  });

  bindModals();
  bindIngestForm();
  bindSidebarToggle();

  // Initial API status check
  await checkApiStatus();
  if (!apiOnline) {
    showToast('ARAN backend is not reachable. Start the Java server first.', 'error', 6000);
  }

  // Load default page
  await navigate('dashboard');
});
