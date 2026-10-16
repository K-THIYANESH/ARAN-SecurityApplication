import { api } from '../api.js';
import { showToast } from '../notifications.js';
import { escHtml } from '../utils.js';

export async function renderReports(container) {
  container.innerHTML = `
    <div class="card">
      <div class="report-card">
        <h4>Generate Security Operations Report</h4>
        <p>
          Generates a comprehensive security report including all events, threats, incidents,
          risk statistics, and severity breakdown. The report is saved to the <code style="background:var(--panel2);padding:2px 6px;border-radius:4px">reports/</code>
          directory on the server.
        </p>
        <button class="primary-btn" id="gen-btn" style="font-size:0.95rem;padding:11px 22px">
          📄 Generate Report Now
        </button>
      </div>
    </div>
    <div class="card" id="report-result" style="display:none">
      <div style="padding:20px">
        <h4 style="margin-bottom:12px;color:var(--green)">✓ Report Generated</h4>
        <div id="report-details"></div>
      </div>
    </div>
    <div class="card">
      <div style="padding:20px">
        <h4 style="margin-bottom:12px">What's Included</h4>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px">
          ${[
            ['📊','Executive Summary','Total events, threats, incidents, open incident count, average risk score'],
            ['⚡','Threat Findings','All detected threats with type, severity, risk score, and explanation'],
            ['🚨','Incident Log','All incidents with ID, title, status, and risk score'],
            ['📈','Severity Breakdown','Count of CRITICAL / HIGH / MEDIUM / LOW threats'],
          ].map(([icon,title,desc])=>`
            <div style="background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:14px">
              <div style="font-size:1.4rem;margin-bottom:8px">${icon}</div>
              <div style="font-weight:600;margin-bottom:6px">${title}</div>
              <div style="color:var(--muted);font-size:0.8rem">${desc}</div>
            </div>
          `).join('')}
        </div>
      </div>
    </div>
  `;

  document.getElementById('gen-btn')?.addEventListener('click', async()=>{
    const btn=document.getElementById('gen-btn');
    btn.disabled=true; btn.textContent='⏳ Generating…';
    try {
      const result = await api.generateReport();
      showToast('Report generated: '+result.fileName, 'success', 5000);
      const resultCard=document.getElementById('report-result');
      const details=document.getElementById('report-details');
      if(resultCard&&details){
        resultCard.style.display='block';
        details.innerHTML=`
          <div style="display:grid;gap:10px">
            <div style="display:flex;gap:16px;flex-wrap:wrap">
              <div><span style="color:var(--muted);font-size:0.8rem">File Name</span><br><code style="color:var(--cyan)">${escHtml(result.fileName)}</code></div>
              <div><span style="color:var(--muted);font-size:0.8rem">Full Path</span><br><code style="color:var(--muted);font-size:0.82rem">${escHtml(result.path)}</code></div>
            </div>
            <p style="color:var(--muted);font-size:0.83rem">${escHtml(result.message||'')}</p>
          </div>
        `;
      }
    } catch(e) {
      showToast('Report generation failed: '+e.message,'error');
    } finally {
      btn.disabled=false; btn.textContent='📄 Generate Report Now';
    }
  });

  return { refresh: ()=>{} };
}
