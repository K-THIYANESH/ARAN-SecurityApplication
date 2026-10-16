import { api } from '../api.js';
import { fmt, sevBadge, statusBadge, emptyState, escHtml } from '../utils.js';
import { showToast } from '../notifications.js';

let pollInterval = null;

export async function renderMonitoring(container) {
  container.innerHTML = `
    <div class="card">
      <div class="monitor-status-card">
        <div class="monitor-status-info">
          <div class="monitor-indicator off" id="mon-indicator"></div>
          <div class="monitor-info">
            <h4 id="mon-title">Checking monitor status…</h4>
            <p id="mon-desc">Polling backend…</p>
          </div>
        </div>
        <div class="monitor-controls">
          <button class="primary-btn" id="mon-start-btn" disabled>▶ Start Monitor</button>
          <button class="danger-btn"  id="mon-stop-btn"  disabled>■ Stop Monitor</button>
        </div>
      </div>
    </div>
    <div class="grid-2-equal">
      <div class="card">
        <div class="card-head"><h3>Recently Detected Events</h3><span class="card-meta" id="mon-ev-meta"></span></div>
        <div class="table-wrap">
          <table class="data-table">
            <thead><tr><th>Time</th><th>User</th><th>Type</th><th>IP</th><th>Severity</th></tr></thead>
            <tbody id="mon-ev-tbody"></tbody>
          </table>
        </div>
        <div id="mon-ev-empty" style="display:none"></div>
      </div>
      <div class="card">
        <div class="card-head"><h3>Recent Threats Detected</h3></div>
        <div class="table-wrap">
          <table class="data-table">
            <thead><tr><th>Type</th><th>Severity</th><th>Risk</th><th>Time</th></tr></thead>
            <tbody id="mon-th-tbody"></tbody>
          </table>
        </div>
        <div id="mon-th-empty" style="display:none"></div>
      </div>
    </div>
    <div class="card" style="padding:16px 20px">
      <h3 style="margin-bottom:10px">Log Format Reference</h3>
      <p style="color:var(--muted);font-size:0.85rem;margin-bottom:12px">
        ARAN monitors <code style="background:var(--panel2);padding:2px 6px;border-radius:4px">logs/security-events.log</code>
        for new lines. Append events in this pipe-delimited format:
      </p>
      <pre style="background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:14px;font-size:0.82rem;overflow-x:auto;color:var(--cyan)">username|eventType|ipAddress|details

# Examples:
admin|LOGIN_FAILURE|203.0.113.10|invalid password
jsmith|SENSITIVE_FILE_ACCESS|10.0.0.45|finance/payroll.csv
sysop|USB_INSERTED|192.168.1.100|USB drive connected
attacker|MALWARE_DETECTED|198.51.100.1|dropper.exe</pre>
      <p style="color:var(--muted);font-size:0.8rem;margin-top:10px">
        On Windows: <code style="background:var(--panel2);padding:2px 6px;border-radius:4px">echo admin^|LOGIN_FAILURE^|10.0.0.1^|test >> logs\security-events.log</code>
      </p>
    </div>
  `;

  async function loadStatus() {
    try {
      const status = await api.monitorStatus();
      const active = status.monitoring === true || status.status === 'ACTIVE';
      const ind    = document.getElementById('mon-indicator');
      const title  = document.getElementById('mon-title');
      const desc   = document.getElementById('mon-desc');
      const startB = document.getElementById('mon-start-btn');
      const stopB  = document.getElementById('mon-stop-btn');

      ind&&(ind.className='monitor-indicator'+(active?'':' off'));
      title&&(title.textContent=active?'Monitoring ACTIVE':'Monitoring INACTIVE');
      desc&&(desc.textContent=active
        ?'Watching logs/security-events.log for new events in real-time.'
        :'Monitor is not running. Click Start to begin automatic log detection.');
      if(startB){ startB.disabled=active; startB.textContent=active?'Running…':'▶ Start Monitor'; }
      if(stopB){  stopB.disabled=!active; }
    } catch(e) {
      const title=document.getElementById('mon-title');
      if(title) title.textContent='Monitor status unknown — backend unreachable';
    }
  }

  async function loadLiveData() {
    try {
      const [evData, thData] = await Promise.all([api.events(8), api.threats(8)]);
      renderMonEvents(evData.events||[]);
      renderMonThreats(thData.threats||[]);
    } catch(e) { /* silently skip on poll error */ }
  }

  function renderMonEvents(events) {
    const tbody=document.getElementById('mon-ev-tbody');
    const empty=document.getElementById('mon-ev-empty');
    const meta =document.getElementById('mon-ev-meta');
    if(!tbody)return;
    meta&&(meta.textContent=`${events.length} recent`);
    if(!events.length){
      tbody.innerHTML='';
      empty.style.display='block';
      empty.innerHTML=emptyState('No events detected yet.','Start monitor and append to the log file.');
      return;
    }
    empty.style.display='none';
    tbody.innerHTML=events.map(e=>`<tr>
      <td class="mono">${fmt(e.timestamp)}</td>
      <td>${escHtml(e.username)}</td>
      <td>${escHtml(e.eventType)}</td>
      <td class="mono">${escHtml(e.ipAddress)}</td>
      <td>${sevBadge(e.severity)}</td>
    </tr>`).join('');
  }

  function renderMonThreats(threats) {
    const tbody=document.getElementById('mon-th-tbody');
    const empty=document.getElementById('mon-th-empty');
    if(!tbody)return;
    if(!threats.length){
      tbody.innerHTML='';
      empty.style.display='block';
      empty.innerHTML=emptyState('No threats detected yet.');
      return;
    }
    empty.style.display='none';
    tbody.innerHTML=threats.map(t=>`<tr>
      <td><strong>${escHtml(t.type)}</strong></td>
      <td>${sevBadge(t.severity)}</td>
      <td><strong>${t.riskScore}</strong></td>
      <td class="mono">${fmt(t.timestamp)}</td>
    </tr>`).join('');
  }

  document.getElementById('mon-start-btn')?.addEventListener('click', async()=>{
    const btn=document.getElementById('mon-start-btn');
    btn.disabled=true; btn.textContent='Starting…';
    try {
      await api.startMonitor();
      showToast('Log monitor started.','success');
      await loadStatus();
    } catch(e) { showToast('Failed: '+e.message,'error'); btn.disabled=false; btn.textContent='▶ Start Monitor'; }
  });

  document.getElementById('mon-stop-btn')?.addEventListener('click', async()=>{
    const btn=document.getElementById('mon-stop-btn');
    btn.disabled=true;
    try {
      await api.stopMonitor();
      showToast('Log monitor stopped.','info');
      await loadStatus();
    } catch(e) { showToast('Failed: '+e.message,'error'); btn.disabled=false; }
  });

  await loadStatus();
  await loadLiveData();

  // Poll every 3 seconds
  if(pollInterval) clearInterval(pollInterval);
  pollInterval=setInterval(async()=>{ await loadStatus(); await loadLiveData(); }, 3000);

  return {
    refresh: async()=>{ await loadStatus(); await loadLiveData(); },
    destroy: ()=>{ if(pollInterval){ clearInterval(pollInterval); pollInterval=null; } }
  };
}
