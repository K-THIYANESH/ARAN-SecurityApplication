import { api } from '../api.js';
import { renderThreatBarChart } from '../charts.js';
import { fmt, sevBadge, riskLabel, riskClass, emptyState, escHtml } from '../utils.js';
import { showToast } from '../notifications.js';

export async function renderRisk(container) {
  container.innerHTML = `
    <div class="kpi-grid" style="grid-template-columns:repeat(auto-fill,minmax(180px,1fr))">
      <div class="card kpi-card" id="r-avg"></div>
      <div class="card kpi-card" id="r-level"></div>
      <div class="card kpi-card" id="r-crit"></div>
      <div class="card kpi-card" id="r-high"></div>
    </div>
    <div class="grid-2">
      <div class="card">
        <div class="card-head"><h3>Threat Severity Breakdown</h3></div>
        <div class="chart-wrap"><canvas id="riskBarChart"></canvas></div>
      </div>
      <div class="card">
        <div class="card-head"><h3>Highest Risk Threats</h3></div>
        <div class="table-wrap">
          <table class="data-table">
            <thead><tr><th>Type</th><th>Severity</th><th>Score</th><th>Explanation</th></tr></thead>
            <tbody id="risk-top-tbody"></tbody>
          </table>
        </div>
        <div id="risk-top-empty" style="display:none"></div>
      </div>
    </div>
    <div class="card">
      <div class="card-head"><h3>Recent High-Risk Events</h3></div>
      <div class="table-wrap">
        <table class="data-table">
          <thead><tr><th>Time</th><th>User</th><th>Event Type</th><th>IP</th><th>Severity</th><th>Details</th></tr></thead>
          <tbody id="risk-ev-tbody"></tbody>
        </table>
      </div>
      <div id="risk-ev-empty" style="display:none"></div>
    </div>
  `;

  async function load() {
    try {
      const [risk, threats, events] = await Promise.all([
        api.riskSummary(), api.threats(), api.events()
      ]);

      // KPIs
      kpiCard('r-avg',   'Average Risk',    (risk.averageRisk??0)+'/100', riskClass(risk.averageRisk));
      kpiCard('r-level', 'Risk Level',       risk.riskLevel||'LOW',      riskClass(risk.averageRisk));
      kpiCard('r-crit',  'Critical Threats', risk.criticalThreats??0,    'critical');
      kpiCard('r-high',  'High Threats',     risk.highThreats??0,        'high');

      // Bar chart
      renderThreatBarChart('riskBarChart',{
        low:risk.lowThreats, medium:risk.mediumThreats,
        high:risk.highThreats, critical:risk.criticalThreats
      });

      // Top threats table
      const topThreats = (threats.threats||[]).sort((a,b)=>b.riskScore-a.riskScore).slice(0,8);
      const topTbody=document.getElementById('risk-top-tbody');
      const topEmpty=document.getElementById('risk-top-empty');
      if(!topThreats.length){
        topTbody.innerHTML='';
        topEmpty.style.display='block';
        topEmpty.innerHTML=emptyState('No threats yet.');
      } else {
        topEmpty.style.display='none';
        topTbody.innerHTML=topThreats.map(t=>`<tr>
          <td><strong>${escHtml(t.type)}</strong></td>
          <td>${sevBadge(t.severity)}</td>
          <td><strong>${t.riskScore}</strong></td>
          <td style="max-width:180px;white-space:normal;line-height:1.4;font-size:0.8rem">${escHtml(t.explanation)||'—'}</td>
        </tr>`).join('');
      }

      // High-risk events
      const highEvents = (events.events||[]).filter(e=>['HIGH','CRITICAL'].includes((e.severity||'').toUpperCase())).slice(0,10);
      const evTbody=document.getElementById('risk-ev-tbody');
      const evEmpty=document.getElementById('risk-ev-empty');
      if(!highEvents.length){
        evTbody.innerHTML='';
        evEmpty.style.display='block';
        evEmpty.innerHTML=emptyState('No high-risk events recorded.');
      } else {
        evEmpty.style.display='none';
        evTbody.innerHTML=highEvents.map(e=>`<tr>
          <td class="mono">${fmt(e.timestamp)}</td>
          <td>${escHtml(e.username)}</td>
          <td>${escHtml(e.eventType)}</td>
          <td class="mono">${escHtml(e.ipAddress)}</td>
          <td>${sevBadge(e.severity)}</td>
          <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(e.details)||'—'}</td>
        </tr>`).join('');
      }
    } catch(e) { showToast('Risk data unavailable: '+e.message,'error'); }
  }

  function kpiCard(id, label, val, cls) {
    const el=document.getElementById(id);
    if(!el)return;
    el.innerHTML=`<div class="kpi-label">${label}</div><div class="kpi-val">${escHtml(String(val))}</div>`;
  }

  await load();
  return { refresh: load };
}
