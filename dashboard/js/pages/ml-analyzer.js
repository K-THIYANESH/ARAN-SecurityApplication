import { api } from '../api.js';
import { showToast } from '../notifications.js';
import { escHtml } from '../utils.js';

const DEMOS = {
  safe: `alice|LOGIN_SUCCESS|192.168.1.24|normal dashboard login
alice|FILE_ACCESS|192.168.1.24|read course timetable.pdf
bob|LOGIN_SUCCESS|10.0.0.15|routine authenticated session`,
  review: `analyst1|LOGIN_FAILURE|203.0.113.20|invalid password
analyst1|USB_INSERTED|10.0.0.15|USB drive connected for file transfer
analyst1|SENSITIVE_FILE_ACCESS|10.0.0.15|finance/payroll.csv`,
  block: `attacker|MALWARE_DETECTED|198.51.100.77|known malicious dropper.exe ransomware payload
attacker|DATA_EXFILTRATION|198.51.100.77|credential archive exfil to suspicious outbound upload
root|PRIVILEGE_ESCALATION|198.51.100.77|unexpected admin privilege escalation`
};

export async function renderMLAnalyzer(container) {
  container.innerHTML = `
    <div class="card" style="border:1px solid rgba(0,229,255,.25);background:linear-gradient(135deg,var(--panel),rgba(0,229,255,.035))">
      <div class="card-head">
        <div>
          <h3 style="font-size:1.25rem">ML Log Analyzer</h3>
          <p style="color:var(--muted);margin-top:5px">Upload a security log. ARAN classifies every event as SAFE, MANUAL REVIEW, or BLOCK.</p>
        </div>
        <span id="ml-engine-badge" class="status-pill">Checking model…</span>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:14px">
        <div>
          <label class="form-label">Security log file
            <input id="ml-file" type="file" accept=".log,.txt,.csv" style="width:100%;margin-top:8px">
          </label>
          <p style="font-size:.78rem;color:var(--muted);margin-top:7px">Expected format: <code>username|eventType|ipAddress|details</code></p>
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:13px">
            <button class="secondary-btn" id="demo-safe">Load Safe Demo</button>
            <button class="secondary-btn" id="demo-review">Load Review Demo</button>
            <button class="secondary-btn" id="demo-block">Load Block Demo</button>
          </div>
        </div>
        <div>
          <label class="form-label">Or paste log content
            <textarea id="ml-content" rows="7" placeholder="alice|LOGIN_SUCCESS|192.168.1.24|normal login"></textarea>
          </label>
        </div>
      </div>
      <div style="display:flex;justify-content:flex-end;gap:10px;margin-top:16px">
        <button class="secondary-btn" id="ml-clear">Clear</button>
        <button class="primary-btn" id="ml-analyze">Analyze Log</button>
      </div>
    </div>

    <div id="ml-summary" style="display:none"></div>
    <div class="card" id="ml-results-card" style="display:none">
      <div class="card-head"><h3>Line-by-Line Decisions</h3><span id="ml-result-meta" class="card-meta"></span></div>
      <div class="table-wrap">
        <table class="data-table">
          <thead><tr><th>Line</th><th>Event</th><th>Decision</th><th>Confidence</th><th>Risk Signals</th><th>Engine</th></tr></thead>
          <tbody id="ml-results"></tbody>
        </table>
      </div>
    </div>


  `;

  const file=document.getElementById('ml-file');
  const content=document.getElementById('ml-content');
  const analyze=document.getElementById('ml-analyze');

  function loadDemo(kind) {
    content.value=DEMOS[kind];
    file.value='';
    showToast(`${kind.toUpperCase()} demo loaded.`, 'info');
  }
  document.getElementById('demo-safe').onclick=()=>loadDemo('safe');
  document.getElementById('demo-review').onclick=()=>loadDemo('review');
  document.getElementById('demo-block').onclick=()=>loadDemo('block');
  document.getElementById('ml-clear').onclick=()=>{
    file.value=''; content.value='';
    document.getElementById('ml-summary').style.display='none';
    document.getElementById('ml-results-card').style.display='none';
  };

  file.addEventListener('change', async()=>{
    const f=file.files?.[0];
    if(!f)return;
    content.value=await f.text();
  });

  async function analyzeLog() {
    let text=content.value.trim();
    if(!text) { showToast('Choose a log file or paste log content first.','error'); return; }
    analyze.disabled=true; analyze.textContent='Analyzing…';
    try {
      const filename=file.files?.[0]?.name || 'pasted-log.log';
      const data=await api.analyzeMLLog({filename,content:text});
      renderResults(data);
      showToast(`Analysis complete: ${data.blocked} block, ${data.manualReview} review, ${data.safe} safe.`, 'success');
    } catch(e) {
      showToast('ML analysis failed: '+e.message,'error');
    } finally {
      analyze.disabled=false; analyze.textContent='Analyze Log';
    }
  }
  analyze.onclick=analyzeLog;

  function decisionBadge(decision) {
    const cls=decision==='BLOCK'?'danger':decision==='MANUAL_REVIEW'?'warning':'ok';
    const label=decision==='MANUAL_REVIEW'?'MANUAL REVIEW':decision;
    return `<span class="badge ${cls}">${label}</span>`;
  }

  function renderResults(data) {
    const summary=document.getElementById('ml-summary');
    summary.style.display='grid';
    summary.style.gridTemplateColumns='repeat(4,1fr)';
    summary.style.gap='12px';
    summary.style.margin='16px 0';
    summary.innerHTML=[
      ['SAFE',data.safe,'ok'],
      ['MANUAL REVIEW',data.manualReview,'warning'],
      ['BLOCK',data.blocked,'danger'],
      ['REJECTED',data.rejectedLines,'muted']
    ].map(x=>`<div class="card" style="padding:17px"><div style="color:var(--muted);font-size:.72rem">${x[0]}</div><div style="font-size:1.7rem;font-weight:800" class="${x[2]}">${x[1]}</div></div>`).join('');

    const badge=document.getElementById('ml-engine-badge');
    badge.textContent=data.modelAvailable?'● ML MODEL ONLINE':'● FALLBACK MODE';
    badge.style.color=data.modelAvailable?'var(--green)':'var(--amber)';

    const tbody=document.getElementById('ml-results');
    tbody.innerHTML=(data.results||[]).map(r=>{
      const signals=[
        r.eventType,
        r.blockProbability>=.35?'block signal': '',
        r.reviewProbability>=.35?'review signal':''
      ].filter(Boolean).map(escHtml).join(' · ');
      return `<tr>
        <td class="mono">${r.line}</td>
        <td><strong>${escHtml(r.eventType||'INVALID')}</strong><br><span style="color:var(--muted);font-size:.72rem">${escHtml(r.username||'')}</span></td>
        <td>${decisionBadge(r.decision)}</td>
        <td><strong>${Math.round((r.confidence||0)*100)}%</strong><div style="font-size:.68rem;color:var(--muted)">S ${(r.safeProbability||0).toFixed(2)} · R ${(r.reviewProbability||0).toFixed(2)} · B ${(r.blockProbability||0).toFixed(2)}</div></td>
        <td style="font-size:.75rem">${signals||'—'}<br><span style="color:var(--muted)">${escHtml(r.explanation||'')}</span></td>
        <td><span class="card-meta">${r.modelUsed?'ML':'FALLBACK'}</span></td>
      </tr>`;
    }).join('');
    document.getElementById('ml-result-meta').textContent=`${data.filename} · ${data.validLines} accepted`;
    document.getElementById('ml-results-card').style.display='block';
  }

  try {
    const d=await api.mlStatus();
    const b=document.getElementById('ml-engine-badge');
    b.textContent=d.modelAvailable?'● ML MODEL ONLINE':'● FALLBACK MODE';
    b.style.color=d.modelAvailable?'var(--green)':'var(--amber)';
  } catch(e) {
    document.getElementById('ml-engine-badge').textContent='● API OFFLINE';
  }

  return { refresh: async()=>{} };
}
