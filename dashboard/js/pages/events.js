import { api } from '../api.js';
import { fmt, sevBadge, emptyState, escHtml, debounce } from '../utils.js';
import { showToast } from '../notifications.js';

export async function renderEvents(container) {
  container.innerHTML = `
    <div class="card">
      <div class="card-head">
        <h3>Security Events</h3>
        <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
          <input type="search" id="ev-q" placeholder="Search user/type/IP…" style="background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:7px 12px;color:var(--text);width:200px">
          <select id="ev-sev" style="background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:7px 12px;color:var(--text)">
            <option value="">All Severity</option>
            <option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option>
          </select>
          <select id="ev-type" style="background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:7px 12px;color:var(--text)">
            <option value="">All Types</option>
            <option>LOGIN_SUCCESS</option><option>LOGIN_FAILURE</option><option>FILE_ACCESS</option>
            <option>SENSITIVE_FILE_ACCESS</option><option>USB_INSERTED</option>
            <option>MALWARE_DETECTED</option><option>PRIVILEGE_ESCALATION</option>
            <option>NETWORK_SCAN</option><option>DATA_EXFILTRATION</option>
          </select>
          <button class="secondary-btn" id="ev-refresh">↺ Refresh</button>
        </div>
      </div>
      <div class="table-wrap">
        <table class="data-table">
          <thead><tr>
            <th>Timestamp</th><th>User</th><th>Event Type</th><th>IP Address</th>
            <th>Source</th><th>Severity</th><th>Details</th>
          </tr></thead>
          <tbody id="ev-tbody"><tr><td colspan="7" class="loading-row"><span class="spinner"></span></td></tr></tbody>
        </table>
      </div>
      <div id="ev-empty" style="display:none"></div>
      <div class="pagination"><span id="ev-count" style="color:var(--muted)"></span></div>
    </div>
  `;

  let all = [];

  function filter() {
    const q   = (document.getElementById('ev-q')?.value||'').toLowerCase();
    const sev = (document.getElementById('ev-sev')?.value||'').toUpperCase();
    const typ = (document.getElementById('ev-type')?.value||'').toUpperCase();
    const res = all.filter(e=>
      (!q||e.username?.toLowerCase().includes(q)||e.eventType?.toLowerCase().includes(q)||e.ipAddress?.includes(q))&&
      (!sev||e.severity?.toUpperCase()===sev)&&
      (!typ||e.eventType?.toUpperCase()===typ)
    );
    render(res);
  }

  function render(events) {
    const tbody=document.getElementById('ev-tbody');
    const empty=document.getElementById('ev-empty');
    const count=document.getElementById('ev-count');
    if(!tbody)return;
    count&&(count.textContent=`Showing ${events.length} of ${all.length} events`);
    if(!events.length){
      tbody.innerHTML='';
      empty.style.display='block';
      empty.innerHTML=emptyState('No events match your filter.','Try clearing the search or changing filters.');
      return;
    }
    empty.style.display='none';
    tbody.innerHTML=events.map(e=>`<tr>
      <td class="mono">${fmt(e.timestamp)}</td>
      <td><strong>${escHtml(e.username)}</strong></td>
      <td>${escHtml(e.eventType)}</td>
      <td class="mono">${escHtml(e.ipAddress)}</td>
      <td>${escHtml(e.source)}</td>
      <td>${sevBadge(e.severity)}</td>
      <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(e.details)}">${escHtml(e.details)||'—'}</td>
    </tr>`).join('');
  }

  const debouncedFilter = debounce(filter, 250);
  document.getElementById('ev-q')?.addEventListener('input', debouncedFilter);
  document.getElementById('ev-sev')?.addEventListener('change', filter);
  document.getElementById('ev-type')?.addEventListener('change', filter);
  document.getElementById('ev-refresh')?.addEventListener('click', load);

  async function load() {
    try {
      const data = await api.events();
      all = data.events || [];
      filter();
    } catch(e) { showToast('Failed to load events: '+e.message,'error'); }
  }

  await load();
  return { refresh: load };
}
