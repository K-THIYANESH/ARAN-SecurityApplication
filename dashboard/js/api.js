/**
 * ARAN API wrapper — single source for all backend communication.
 * All fetch() calls go through here; never scatter them across files.
 */

const BASE = '';  // Same origin (Java serves dashboard)

export async function apiFetch(path, options = {}) {
  const url = BASE + path;
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options
  });
  const ct = res.headers.get('content-type') || '';
  const data = ct.includes('application/json') ? await res.json() : await res.text();
  if (!res.ok) {
    const msg = (data && data.error) ? data.error : `HTTP ${res.status}`;
    throw new Error(msg);
  }
  return data;
}

export const api = {
  health:          () => apiFetch('/api/health'),
  summary:         () => apiFetch('/api/dashboard/summary'),
  events:          (limit) => apiFetch('/api/events' + (limit ? `?limit=${limit}` : '')),
  threats:         (limit) => apiFetch('/api/threats' + (limit ? `?limit=${limit}` : '')),
  incidents:       (limit) => apiFetch('/api/incidents' + (limit ? `?limit=${limit}` : '')),
  riskSummary:     () => apiFetch('/api/risk/summary'),
  monitorStatus:   () => apiFetch('/api/monitoring/status'),
  startMonitor:    () => apiFetch('/api/monitor/start', { method: 'POST' }),
  stopMonitor:     () => apiFetch('/api/monitor/stop',  { method: 'POST' }),
  ingestEvent:     (payload) => apiFetch('/api/event', { method: 'POST', body: JSON.stringify(payload) }),
  runSimulation:   () => apiFetch('/api/simulation/run', { method: 'POST' }),
  mlStatus:        () => apiFetch('/api/ml/status'),
  analyzeMLLog:     (payload) => apiFetch('/api/ml/analyze', { method: 'POST', body: JSON.stringify(payload) }),
  generateReport:  () => apiFetch('/api/reports/generate', { method: 'POST' }),
  getIncident:     (id) => apiFetch(`/api/incidents/${id}`),
  updateIncident:  (id, status) => apiFetch(`/api/incidents/${id}`, {
    method: 'PATCH',
    body: JSON.stringify({ status })
  }),
};
