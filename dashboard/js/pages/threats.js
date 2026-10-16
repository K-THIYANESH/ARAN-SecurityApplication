import { api } from '../api.js';
import { fmt, sevBadge, emptyState, escHtml, debounce } from '../utils.js';
import { showToast } from '../notifications.js';

export async function renderThreats(container) {
  container.innerHTML = `
    <div class="card">
      <div class="card-head">
        <h3>Threat Findings</h3>
        <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
          <input type="search" id="th-q" placeholder="Search…" style="background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:7px 12px;color:var(--text);width:180px">
          <select id="th-sev" style="background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:7px 12px;color:var(--text)">
            <option value="">All Severity</option>
            <option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option>
          </select>
          <button class="secondary-btn" id="th-refresh">↺ Refresh</button>
        </div>
      </div>
      <div class="table-wrap">
        <table class="data-table">
          <thead><tr>
            <th>Threat ID</th><th>Type</th><th>Severity</th><th>Risk Score</th>
            <th>Explanation</th><th>Event ID</th><th>Detected</th>
          </tr></thead>
          <tbody id="th-tbody"><tr><td colspan="7" class="loading-row"><span class="spinner"></span></td></tr></tbody>
        </table>
      </div>
      <div id="th-empty" style="display:none"></div>
      <div class="pagination"><span id="th-count" style="color:var(--muted)"></span></div>
    </div>
  `;

  let all = [];

  function filter() {
    const q   = (document.getElementById('th-q')?.value||'').toLowerCase();
    const sev = (document.getElementById('th-sev')?.value||'').toUpperCase();
    const res = all.filter(t=>
      (!q||t.type?.toLowerCase().includes(q)||t.explanation?.toLowerCase().includes(q))&&
      (!sev||t.severity?.toUpperCase()===sev)
    );
    render(res);
  }

  function render(threats) {
    const tbody=document.getElementById('th-tbody');
    const empty=document.getElementById('th-empty');
    const count=document.getElementById('th-count');
    if(!tbody)return;
    count&&(count.textContent=`Showing ${threats.length} of ${all.length} threats`);
    if(!threats.length){
      tbody.innerHTML='';
      empty.style.display='block';
      empty.innerHTML=emptyState('No threats match your filter.');
      return;
    }
    empty.style.display='none';
    tbody.innerHTML=threats.map(t=>`<tr>
      <td class="mono" style="font-size:0.73rem">${escHtml(t.id?.substring(0,12))}…</td>
      <td><strong>${escHtml(t.type)}</strong></td>
      <td>${sevBadge(t.severity)}</td>
      <td><strong style="font-size:1.05rem">${t.riskScore}</strong></td>
      <td style="max-width:220px;white-space:normal;line-height:1.4">${escHtml(t.explanation)||'—'}</td>
      <td class="mono" style="font-size:0.73rem">${escHtml(t.eventId?.substring(0,12))}…</td>
      <td class="mono">${fmt(t.timestamp)}</td>
    </tr>`).join('');
  }

  const df = debounce(filter, 250);
  document.getElementById('th-q')?.addEventListener('input', df);
  document.getElementById('th-sev')?.addEventListener('change', filter);
  document.getElementById('th-refresh')?.addEventListener('click', load);

  async function load() {
    try {
      const data = await api.threats();
      all = data.threats||[];
      filter();
    } catch(e) { showToast('Failed to load threats: '+e.message,'error'); }
  }

  await load();
  return { refresh: load };
}
