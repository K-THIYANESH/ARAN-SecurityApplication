/**
 * Shared utilities used across all page modules.
 */

export function fmt(value) {
  if (!value) return '—';
  try {
    const d = new Date(value);
    if (isNaN(d)) return value;
    return d.toLocaleString('en-GB', { day:'2-digit', month:'short', hour:'2-digit', minute:'2-digit', second:'2-digit' });
  } catch { return value; }
}

export function sevBadge(sev) {
  const s = (sev || 'low').toLowerCase();
  return `<span class="sev ${s}">${(sev || 'LOW').toUpperCase()}</span>`;
}

export function statusBadge(status) {
  const s = (status || 'open').toLowerCase();
  return `<span class="sev ${s}">${(status || 'OPEN').toUpperCase()}</span>`;
}

export function badge(text, cls) {
  return `<span class="badge ${cls}">${text}</span>`;
}

export function escHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export function emptyState(msg, sub = '') {
  return `<div class="empty"><p>${escHtml(msg)}</p>${sub ? `<p>${escHtml(sub)}</p>` : ''}</div>`;
}

export function loadingRow(cols) {
  return `<tr><td colspan="${cols}" class="loading-row"><span class="spinner"></span></td></tr>`;
}

export function riskClass(score) {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 30) return 'medium';
  return 'low';
}

export function riskLabel(score) {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 30) return 'MEDIUM';
  return 'LOW';
}

export function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}
