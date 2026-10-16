/**
 * Chart.js chart management.
 * All chart instances tracked here to allow clean destruction/re-render.
 */
const instances = {};

export function destroyChart(id) {
  if (instances[id]) { instances[id].destroy(); delete instances[id]; }
}

export function renderSeverityChart(canvasId, data) {
  const ctx = document.getElementById(canvasId);
  if (!ctx || !window.Chart) return;
  destroyChart(canvasId);
  const { low = 0, medium = 0, high = 0, critical = 0 } = data;
  const total = low + medium + high + critical;
  instances[canvasId] = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
      datasets: [{
        data: [low, medium, high, critical],
        backgroundColor: ['#3de89a', '#f5d76e', '#ff9f43', '#ff4f70'],
        borderWidth: 0,
        hoverOffset: 8,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false, cutout: '65%',
      plugins: {
        legend: { position: 'bottom', labels: { color: '#7fa8c0', usePointStyle: true, padding: 14, font: { size: 11 } } },
        tooltip: { callbacks: {
          label: (ctx) => {
            const pct = total > 0 ? Math.round(ctx.parsed / total * 100) : 0;
            return ` ${ctx.label}: ${ctx.parsed} (${pct}%)`;
          }
        }}
      }
    }
  });
}

export function renderRiskHistoryChart(canvasId, labels, scores) {
  const ctx = document.getElementById(canvasId);
  if (!ctx || !window.Chart) return;
  destroyChart(canvasId);
  instances[canvasId] = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'Risk Score',
        data: scores,
        borderColor: '#38c8f0',
        backgroundColor: 'rgba(56,200,240,0.08)',
        fill: true,
        tension: 0.4,
        pointBackgroundColor: '#38c8f0',
        pointRadius: 4,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#7fa8c0', font: { size: 10 } }, grid: { color: 'rgba(100,180,220,0.08)' } },
        y: { min: 0, max: 100, ticks: { color: '#7fa8c0', font: { size: 10 } }, grid: { color: 'rgba(100,180,220,0.08)' } }
      }
    }
  });
}

export function renderThreatBarChart(canvasId, data) {
  const ctx = document.getElementById(canvasId);
  if (!ctx || !window.Chart) return;
  destroyChart(canvasId);
  const { low = 0, medium = 0, high = 0, critical = 0 } = data;
  instances[canvasId] = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
      datasets: [{
        label: 'Threats',
        data: [low, medium, high, critical],
        backgroundColor: ['rgba(61,232,154,0.5)', 'rgba(245,215,110,0.5)', 'rgba(255,159,67,0.5)', 'rgba(255,79,112,0.5)'],
        borderColor:     ['#3de89a','#f5d76e','#ff9f43','#ff4f70'],
        borderWidth: 1,
        borderRadius: 6,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#7fa8c0' }, grid: { display: false } },
        y: { ticks: { color: '#7fa8c0', stepSize: 1 }, grid: { color: 'rgba(100,180,220,0.08)' }, beginAtZero: true }
      }
    }
  });
}
