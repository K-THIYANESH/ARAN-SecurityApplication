import { api } from '../api.js';
import { escHtml } from '../utils.js';
import { showToast } from '../notifications.js';

export async function renderSystem(container) {
  container.innerHTML = `
    <div class="card">
      <div class="card-head"><h3>System Health</h3><button class="secondary-btn" id="sys-refresh">↺ Refresh</button></div>
      <div class="system-grid" id="sys-grid">
        <div class="loading-row" style="grid-column:1/-1"><span class="spinner"></span></div>
      </div>
    </div>
    <div class="card" style="margin-top:0">
      <div style="padding:20px">
        <h4 style="margin-bottom:12px">API Endpoint Reference</h4>
        <table class="data-table">
          <thead><tr><th>Method</th><th>Endpoint</th><th>Description</th></tr></thead>
          <tbody>
            ${[
              ['GET','/api/health','Server status and basic metrics'],
              ['GET','/api/events','All security events (optional ?limit=N)'],
              ['GET','/api/events/recent','10 most recent events'],
              ['GET','/api/threats','All threat findings'],
              ['GET','/api/threats/recent','10 most recent threats'],
              ['GET','/api/incidents','All incidents'],
              ['GET','/api/incidents/recent','10 most recent incidents'],
              ['GET','/api/incidents/{id}','Single incident by ID'],
              ['PATCH','/api/incidents/{id}','Update incident status'],
              ['GET','/api/dashboard/summary','KPI summary for dashboard'],
              ['GET','/api/risk/summary','Risk score summary'],
              ['GET','/api/monitoring/status','Monitor status'],
              ['POST','/api/monitor/start','Start log monitor'],
              ['POST','/api/monitor/stop','Stop log monitor'],
              ['POST','/api/event','Ingest a security event'],
              ['POST','/api/simulation/run','Run attack simulation'],
              ['POST','/api/reports/generate','Generate security report'],
            ].map(([m,p,d])=>`<tr>
              <td><span class="badge ${m==='GET'?'ok':m==='POST'?'medium':'active'}">${m}</span></td>
              <td class="mono" style="font-size:0.8rem">${p}</td>
              <td style="color:var(--muted);font-size:0.83rem">${d}</td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;

  async function load() {
    try {
      const h = await api.health();
      const grid=document.getElementById('sys-grid');
      if(!grid)return;
      const items=[
        {label:'API Status',     val:'UP',                         ok:true},
        {label:'Service',        val:escHtml(h.service||'ARAN'),   ok:true},
        {label:'Storage Mode',   val:escHtml(h.storageMode||'FILE'),ok:true},
        {label:'Monitoring',     val:h.monitoring?'ACTIVE':'INACTIVE', ok:h.monitoring},
        {label:'Total Events',   val:h.events??'—',                ok:true},
        {label:'Total Threats',  val:h.threats??'—',               ok:true},
      ];
      grid.innerHTML=items.map(it=>`
        <div class="system-item">
          <div class="system-item-label">${it.label}</div>
          <div class="system-item-val" style="color:${it.ok?'var(--green)':'var(--red)'}">${it.val}</div>
        </div>
      `).join('');
    } catch(e) {
      const grid=document.getElementById('sys-grid');
      if(grid) grid.innerHTML=`<div class="system-item" style="grid-column:1/-1"><div class="system-item-label">API Status</div><div class="system-item-val" style="color:var(--red)">UNREACHABLE — ${escHtml(e.message)}</div></div>`;
    }
  }

  document.getElementById('sys-refresh')?.addEventListener('click', load);
  await load();
  return { refresh: load };
}
