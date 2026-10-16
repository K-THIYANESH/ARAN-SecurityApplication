import { api } from '../api.js';
import { renderSeverityChart } from '../charts.js';
import { fmt, sevBadge, statusBadge, riskClass, riskLabel, emptyState, escHtml } from '../utils.js';
import { showToast } from '../notifications.js';

export async function renderDashboard(container) {
  container.innerHTML = `
    <div class="kpi-grid" id="kpi-grid">
      ${[0,1,2,3,4,5].map(i=>`<div class="card kpi-card" id="kpi-${i}"><div class="loading-row"><span class="spinner"></span></div></div>`).join('')}
    </div>
    <div class="grid-2">
      <div class="card">
        <div class="card-head"><h3>Threat Severity Distribution</h3><span class="card-meta">Live data</span></div>
        <div class="chart-wrap"><canvas id="severityChart"></canvas></div>
      </div>
      <div class="card">
        <div class="card-head"><h3>Risk Assessment</h3></div>
        <div class="gauge-section">
          <div class="gauge-ring" id="gauge-ring">
            <div class="gauge-val"><div class="score" id="gauge-score">—</div><div class="label">Risk Score</div></div>
          </div>
          <div class="gauge-metrics" style="width:100%">
            <div class="gauge-row"><span class="k">Risk Level</span><span class="v" id="gauge-level">—</span></div>
            <div class="gauge-row"><span class="k">Critical Threats</span><span class="v" id="gauge-crit">—</span></div>
            <div class="gauge-row"><span class="k">Open Incidents</span><span class="v" id="gauge-open">—</span></div>
          </div>
        </div>
      </div>
    </div>
    <div class="card">
      <div class="card-head">
        <h3>Recent Security Events</h3>
        <div style="display:flex;gap:10px;flex-wrap:wrap">
          <input type="search" id="ev-filter" placeholder="Search…" style="background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:6px 10px;color:var(--text);font-size:0.8rem;width:140px">
          <select id="ev-sev" style="background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:6px 10px;color:var(--text);font-size:0.8rem">
            <option value="">All severity</option>
            <option value="LOW">LOW</option><option value="MEDIUM">MEDIUM</option>
            <option value="HIGH">HIGH</option><option value="CRITICAL">CRITICAL</option>
          </select>
        </div>
      </div>
      <div class="table-wrap">
        <table class="data-table">
          <thead><tr><th>Time</th><th>User</th><th>Event Type</th><th>IP</th><th>Source</th><th>Severity</th><th>Details</th></tr></thead>
          <tbody id="events-tbody"></tbody>
        </table>
      </div>
      <div id="events-empty" style="display:none"></div>
    </div>
    <div class="grid-2-equal">
      <div class="card">
        <div class="card-head">
          <h3>Active Threats</h3>
          <button class="sim-btn" id="sim-btn">▶ Run Simulation</button>
        </div>
        <div class="table-wrap">
          <table class="data-table">
            <thead><tr><th>Type</th><th>Severity</th><th>Risk</th><th>Explanation</th><th>Time</th></tr></thead>
            <tbody id="threats-tbody"></tbody>
          </table>
        </div>
        <div id="threats-empty" style="display:none"></div>
      </div>
      <div class="card">
        <div class="card-head"><h3>Open Incidents</h3></div>
        <div class="table-wrap">
          <table class="data-table">
            <thead><tr><th>ID</th><th>Title</th><th>Risk</th><th>Status</th><th>Created</th></tr></thead>
            <tbody id="incidents-tbody"></tbody>
          </table>
        </div>
        <div id="incidents-empty" style="display:none"></div>
      </div>
    </div>
  `;

  let allEvents = [];

  function applyFilter() {
    const q = (document.getElementById('ev-filter')?.value||'').toLowerCase();
    const sev = (document.getElementById('ev-sev')?.value||'').toUpperCase();
    const filtered = allEvents.filter(e=>
      (!q||e.username?.toLowerCase().includes(q)||e.eventType?.toLowerCase().includes(q)||e.ipAddress?.toLowerCase().includes(q))&&
      (!sev||e.severity?.toUpperCase()===sev)
    );
    renderEvents(filtered);
  }

  document.getElementById('ev-filter')?.addEventListener('input', applyFilter);
  document.getElementById('ev-sev')?.addEventListener('change', applyFilter);

  document.getElementById('sim-btn')?.addEventListener('click', async()=>{
    const btn=document.getElementById('sim-btn');
    btn.disabled=true;btn.textContent='⏳ Running…';
    try{
      await api.runSimulation();
      showToast('Attack simulation complete — dashboard refreshed.','success',4000);
      await load();
    }catch(e){showToast('Simulation failed: '+e.message,'error');}
    finally{btn.disabled=false;btn.textContent='▶ Run Simulation';}
  });

  async function load() {
    try {
      const [summary, evData, thData, incData] = await Promise.all([
        api.summary(), api.events(20), api.threats(10), api.incidents(10)
      ]);
      renderKpis(summary);
      renderGauge(summary);
      renderSeverityChart('severityChart',{low:summary.lowThreats,medium:summary.mediumThreats,high:summary.highThreats,critical:summary.criticalThreats});
      allEvents = evData.events||[];
      applyFilter();
      renderThreats(thData.threats||[]);
      renderIncidents(incData.incidents||[]);
    } catch(e) { showToast('Backend unreachable — '+e.message,'error'); }
  }

  await load();
  return { refresh: load };
}

function renderKpis(s) {
  const defs=[
    {label:'Total Events',    val:s.events??0,          sub:'Ingested',        badge:'LIVE',                              cls:'ok'},
    {label:'Active Threats',  val:s.threats??0,         sub:'Detected',        badge:s.threats>0?'ALERT':'CLEAR',         cls:s.threats>0?'medium':'ok'},
    {label:'Open Incidents',  val:s.openIncidents??0,   sub:'Needs response',  badge:s.openIncidents>0?'OPEN':'CLEAR',    cls:s.openIncidents>0?'high':'ok'},
    {label:'Critical Threats',val:s.criticalThreats??0, sub:'Priority watch',  badge:s.criticalThreats>0?'CRIT':'NONE',  cls:s.criticalThreats>0?'critical':'ok'},
    {label:'Average Risk',    val:(s.averageRisk??0)+'/100', sub:'Threat exposure', badge:riskLabel(s.averageRisk),       cls:riskClass(s.averageRisk)},
    {label:'Monitoring',      val:s.monitoring?'ACTIVE':'INACTIVE', sub:'Background scanner', badge:s.monitoring?'ONLINE':'OFFLINE', cls:s.monitoring?'active':'offline'},
  ];
  defs.forEach((k,i)=>{
    const el=document.getElementById('kpi-'+i);
    if(!el)return;
    el.className='card kpi-card';
    el.innerHTML=`<div class="kpi-label">${k.label}</div><div class="kpi-val">${escHtml(String(k.val))}</div><div class="kpi-foot"><span class="kpi-sub">${k.sub}</span><span class="badge ${k.cls}">${k.badge}</span></div>`;
  });
}

function renderGauge(s) {
  const score=s.averageRisk??0;
  const ring=document.getElementById('gauge-ring');
  if(ring){
    const deg=Math.min(360,score*3.6);
    const col=score>=80?'#ff4f70':score>=60?'#ff9f43':score>=30?'#f5d76e':'#3de89a';
    ring.style.background=`conic-gradient(${col} 0deg ${deg}deg, rgba(255,255,255,0.07) ${deg}deg 360deg)`;
  }
  const sc=document.getElementById('gauge-score'); if(sc) sc.textContent=score+'/100';
  const lv=document.getElementById('gauge-level'); if(lv) lv.textContent=riskLabel(score);
  const cr=document.getElementById('gauge-crit');  if(cr) cr.textContent=s.criticalThreats??0;
  const op=document.getElementById('gauge-open');  if(op) op.textContent=s.openIncidents??0;
}

function renderEvents(events) {
  const tbody=document.getElementById('events-tbody');
  const empty=document.getElementById('events-empty');
  if(!tbody)return;
  if(!events.length){
    tbody.innerHTML='';
    empty.style.display='block';
    empty.innerHTML=emptyState('No security events recorded.','Use Ingest Event or Run Simulation.');
    return;
  }
  empty.style.display='none';
  tbody.innerHTML=events.map(e=>`<tr>
    <td class="mono">${fmt(e.timestamp)}</td>
    <td>${escHtml(e.username)}</td>
    <td>${escHtml(e.eventType)}</td>
    <td class="mono">${escHtml(e.ipAddress)}</td>
    <td>${escHtml(e.source)}</td>
    <td>${sevBadge(e.severity)}</td>
    <td style="max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(e.details)}">${escHtml(e.details)||'—'}</td>
  </tr>`).join('');
}

function renderThreats(threats) {
  const tbody=document.getElementById('threats-tbody');
  const empty=document.getElementById('threats-empty');
  if(!tbody)return;
  if(!threats.length){
    tbody.innerHTML='';
    empty.style.display='block';
    empty.innerHTML=emptyState('No threats detected.','Run Attack Simulation to generate sample threats.');
    return;
  }
  empty.style.display='none';
  tbody.innerHTML=threats.map(t=>`<tr>
    <td><strong>${escHtml(t.type)}</strong></td>
    <td>${sevBadge(t.severity)}</td>
    <td><strong>${t.riskScore}</strong></td>
    <td style="max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(t.explanation)}">${escHtml(t.explanation)||'—'}</td>
    <td class="mono">${fmt(t.timestamp)}</td>
  </tr>`).join('');
}

function renderIncidents(incidents) {
  const tbody=document.getElementById('incidents-tbody');
  const empty=document.getElementById('incidents-empty');
  if(!tbody)return;
  if(!incidents.length){
    tbody.innerHTML='';
    empty.style.display='block';
    empty.innerHTML=emptyState('No incidents.','High-risk threats auto-create incidents.');
    return;
  }
  empty.style.display='none';
  tbody.innerHTML=incidents.map(i=>`<tr>
    <td class="mono" style="font-size:0.75rem">${escHtml(i.id)}</td>
    <td>${escHtml(i.title)}</td>
    <td><strong>${i.riskScore}</strong></td>
    <td>${statusBadge(i.status)}</td>
    <td class="mono">${fmt(i.createdAt)}</td>
  </tr>`).join('');
}
