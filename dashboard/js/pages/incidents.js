import { api } from '../api.js';
import { fmt, statusBadge, emptyState, escHtml, debounce } from '../utils.js';
import { showToast } from '../notifications.js';

export async function renderIncidents(container) {
  container.innerHTML = `
    <div class="card">
      <div class="card-head">
        <h3>Incident Management</h3>
        <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
          <input type="search" id="inc-q" placeholder="Search…" style="background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:7px 12px;color:var(--text);width:180px">
          <select id="inc-status" style="background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:7px 12px;color:var(--text)">
            <option value="">All Statuses</option>
            <option>OPEN</option><option>INVESTIGATING</option><option>CONTAINED</option><option>RESOLVED</option>
          </select>
          <button class="secondary-btn" id="inc-refresh">↺ Refresh</button>
        </div>
      </div>
      <div class="table-wrap">
        <table class="data-table">
          <thead><tr>
            <th>Incident ID</th><th>Title</th><th>Threat ID</th><th>Risk</th>
            <th>Status</th><th>Created</th><th>Updated</th><th>Action</th>
          </tr></thead>
          <tbody id="inc-tbody"><tr><td colspan="8" class="loading-row"><span class="spinner"></span></td></tr></tbody>
        </table>
      </div>
      <div id="inc-empty" style="display:none"></div>
      <div class="pagination"><span id="inc-count" style="color:var(--muted)">Loading…</span></div>
    </div>
    <div style="padding:12px 0 0;color:var(--muted);font-size:0.8rem">
      💡 Change incident status using the dropdown in the Action column. Changes are persisted to the backend immediately.
    </div>
  `;

  let all = [];

  function filter() {
    const q  = (document.getElementById('inc-q')?.value||'').toLowerCase();
    const st = (document.getElementById('inc-status')?.value||'').toUpperCase();
    const res= all.filter(i=>
      (!q||i.title?.toLowerCase().includes(q)||i.id?.toLowerCase().includes(q))&&
      (!st||i.status?.toUpperCase()===st)
    );
    render(res);
  }

  function render(incidents) {
    const tbody=document.getElementById('inc-tbody');
    const empty=document.getElementById('inc-empty');
    const count=document.getElementById('inc-count');
    if(!tbody)return;
    count&&(count.textContent=`Showing ${incidents.length} of ${all.length} incidents`);
    if(!incidents.length){
      tbody.innerHTML='';
      empty.style.display='block';
      empty.innerHTML=emptyState('No incidents match your filter.','High-risk threats create incidents automatically.');
      return;
    }
    empty.style.display='none';
    tbody.innerHTML=incidents.map(i=>`<tr id="inc-row-${escHtml(i.id)}">
      <td class="mono" style="font-size:0.78rem"><strong>${escHtml(i.id)}</strong></td>
      <td>${escHtml(i.title)}</td>
      <td class="mono" style="font-size:0.73rem">${escHtml(i.threatId?.substring(0,12))}…</td>
      <td><strong style="font-size:1.05rem">${i.riskScore}</strong></td>
      <td id="inc-status-cell-${escHtml(i.id)}">${statusBadge(i.status)}</td>
      <td class="mono">${fmt(i.createdAt)}</td>
      <td class="mono">${fmt(i.updatedAt)}</td>
      <td>
        <select class="status-select" data-id="${escHtml(i.id)}" data-current="${escHtml(i.status)}">
          <option value="OPEN"          ${i.status==='OPEN'?'selected':''}>OPEN</option>
          <option value="INVESTIGATING" ${i.status==='INVESTIGATING'?'selected':''}>INVESTIGATING</option>
          <option value="CONTAINED"     ${i.status==='CONTAINED'?'selected':''}>CONTAINED</option>
          <option value="RESOLVED"      ${i.status==='RESOLVED'?'selected':''}>RESOLVED</option>
        </select>
      </td>
    </tr>`).join('');

    // Wire up status change selects
    tbody.querySelectorAll('.status-select').forEach(sel=>{
      sel.addEventListener('change', async(ev)=>{
        const id = ev.target.dataset.id;
        const newStatus = ev.target.value;
        const prev = ev.target.dataset.current;
        if(newStatus===prev) return;
        ev.target.disabled=true;
        try {
          await api.updateIncident(id, newStatus);
          ev.target.dataset.current=newStatus;
          const cell=document.getElementById('inc-status-cell-'+id);
          if(cell) cell.innerHTML=statusBadge(newStatus);
          // Update in all[]
          const inc=all.find(x=>x.id===id);
          if(inc) inc.status=newStatus;
          showToast(`Incident ${id} updated to ${newStatus}.`,'success');
        } catch(err) {
          showToast('Failed to update incident: '+err.message,'error');
          ev.target.value=prev; // revert
        } finally { ev.target.disabled=false; }
      });
    });
  }

  const df = debounce(filter, 250);
  document.getElementById('inc-q')?.addEventListener('input', df);
  document.getElementById('inc-status')?.addEventListener('change', filter);
  document.getElementById('inc-refresh')?.addEventListener('click', load);

  async function load() {
    try {
      const data = await api.incidents();
      all = data.incidents||[];
      filter();
    } catch(e) { showToast('Failed to load incidents: '+e.message,'error'); }
  }

  await load();
  return { refresh: load };
}
