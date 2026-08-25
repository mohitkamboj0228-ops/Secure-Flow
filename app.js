// App Navigation & State
const state = {
  activeTab: 'overview',
  activeScanner: 'semgrep',
  activeIaC: 'tf-vpc',
  activeDoc: 'doc-install',
  securityScore: 100,
  auditBreakdown: [],
  reports: {},
  deployments: [],
  pods: [],
  incidents: [],
  auditLogs: [],
  telemetry: [], // Live metrics data from API
  demoStatus: {
    vulnerability: 1, // 1 = Stable, 2 = Injected, 3 = Resolved
    secret: 1,
    policy: 1,
    failure: 1
  }
};

const API_BASE = window.location.origin;

// Sidebar toggle for responsive layouts
function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  sidebar.classList.toggle('open');
}

// Submenu accordion toggle
function toggleSubmenu(submenuId) {
  const menu = document.getElementById(submenuId);
  const isVisible = menu.style.display === 'flex';
  menu.style.display = isVisible ? 'none' : 'flex';
}

// Navigation controller
function switchNav(tabId, subTarget = null) {
  state.activeTab = tabId;
  
  // Close sidebar on mobile
  document.getElementById('sidebar').classList.remove('open');

  // Handle accordion buttons
  const buttons = document.querySelectorAll('.nav-btn, .sub-btn');
  buttons.forEach(btn => btn.classList.remove('active'));

  // Set active top level button
  const topBtn = document.getElementById(`btn-${tabId}`);
  if (topBtn) topBtn.classList.add('active');

  // Adjust display cards
  const panes = document.querySelectorAll('.tab-pane');
  panes.forEach(pane => {
    if (pane.id === `tab-${tabId}`) {
      pane.classList.add('active');
    } else {
      pane.classList.remove('active');
    }
  });

  // Handle Tab-specific Submenu selections
  if (tabId === 'security' && subTarget) {
    document.getElementById('btn-security').classList.add('active');
    document.getElementById(`btn-sec-${subTarget === 'trivy_sca' ? 'deps' : subTarget === 'gitleaks' ? 'secrets' : 'sast'}`).classList.add('active');
    switchScannerView(subTarget);
  } else if (tabId === 'sbom') {
    document.getElementById('btn-security').classList.add('active');
    document.getElementById('btn-sec-sbom').classList.add('active');
    renderSbom();
  } else if (tabId === 'kubernetes') {
    document.getElementById('btn-k8s').classList.add('active');
    const workloadsView = document.getElementById('k8s-workloads-view');
    const policiesView = document.getElementById('k8s-policies-view');
    
    if (subTarget === 'policies') {
      document.getElementById('btn-k8s-policies').classList.add('active');
      workloadsView.style.display = 'none';
      policiesView.style.display = 'block';
    } else {
      document.getElementById('btn-k8s-workloads').classList.add('active');
      workloadsView.style.display = 'block';
      policiesView.style.display = 'none';
    }
    renderKubernetes();
  } else if (tabId === 'observability') {
    document.getElementById('btn-observability').classList.add('active');
    const metricsView = document.getElementById('obs-metrics-view');
    const logsView = document.getElementById('obs-logs-view');
    
    if (subTarget === 'logs') {
      document.getElementById('btn-obs-logs').classList.add('active');
      metricsView.style.display = 'none';
      logsView.style.display = 'block';
      renderAuditLogs();
    } else {
      document.getElementById('btn-obs-metrics').classList.add('active');
      metricsView.style.display = 'block';
      logsView.style.display = 'none';
      fetchTelemetry();
    }
  } else if (tabId === 'documentation') {
    switchDocTab(state.activeDoc);
  }

  // Update headers
  updateHeaderMeta(tabId);
}

function updateHeaderMeta(tabId) {
  const meta = {
    overview: { title: 'Ecosystem Overview', subtitle: 'Audit software supply chain security posture.' },
    pipelines: { title: 'CI/CD Pipelines', subtitle: 'Integrated scanning validation gates.' },
    security: { title: 'Vulnerability Analysis', subtitle: 'Semgrep, Trivy, and Gitleaks findings logs.' },
    sbom: { title: 'Software Bill of Materials', subtitle: 'CycloneDX dependencies components inventory.' },
    kubernetes: { title: 'Kubernetes Workloads', subtitle: 'Workload rages, namespaces, and Kyverno policy checks.' },
    observability: { title: 'Telemetry & Observability', subtitle: 'Live request SLA gauges and audit log histories.' },
    demo: { title: 'Demo & Chaos Control', subtitle: 'Inject controlled failures to test pipeline policies.' },
    'ai-assistant': { title: 'AI Developer Assistant', subtitle: 'AI recommendations. Engineer verification required.' },
    architecture: { title: 'Platform Architecture Map', subtitle: 'Interactive components design layout.' },
    documentation: { title: 'Platform Documentation', subtitle: 'Troubleshooting guidelines and installation checklists.' }
  };
  
  document.getElementById('current-tab-title').innerText = meta[tabId].title;
  document.getElementById('current-tab-subtitle').innerText = meta[tabId].subtitle;
}

// Initial Loading
window.addEventListener('DOMContentLoaded', () => {
  // Collapse accordions initially
  document.getElementById('sub-security').style.display = 'none';
  document.getElementById('sub-k8s').style.display = 'none';
  document.getElementById('sub-observability').style.display = 'none';

  switchNav('overview');
  fetchData();
  fetchTelemetry();

  // Poll databases
  setInterval(fetchData, 4000);
  setInterval(fetchTelemetry, 3000);
});

// Fetch general db information
async function fetchData() {
  try {
    const statusRes = await fetch(`${API_BASE}/api/status`);
    const statusData = await statusRes.json();
    
    // Server status footer
    const connInd = document.getElementById('conn-indicator');
    const connTxt = document.getElementById('conn-text');
    connInd.className = 'status-indicator success';
    connTxt.innerText = `Online (${statusData.db_type})`;

    // Fetch security audits
    const secRes = await fetch(`${API_BASE}/api/security`);
    const secData = await secRes.json();
    state.securityScore = secData.score;
    state.auditBreakdown = secData.audit;
    state.reports = secData.reports;

    // Fetch workloads
    const depRes = await fetch(`${API_BASE}/api/deployments`);
    const depData = await depRes.json();
    state.deployments = depData.deployments;
    state.pods = depData.pods;

    // Fetch incidents
    const incRes = await fetch(`${API_BASE}/api/incidents`);
    const incData = await incRes.json();
    state.incidents = incData;

    // Fetch audit trail
    const auditRes = await fetch(`${API_BASE}/api/audit`);
    const auditData = await auditRes.json();
    state.auditLogs = auditData;

    updateUI();
  } catch (err) {
    console.warn('[API] Fetch failed. Server offline. Loading simulation fallback...');
    const connInd = document.getElementById('conn-indicator');
    const connTxt = document.getElementById('conn-text');
    if (connInd) {
      connInd.className = 'status-indicator warning';
    }
    if (connTxt) {
      connTxt.innerText = 'Offline (Demo Simulation)';
    }

    // Set fallback simulation values
    state.securityScore = 95;
    state.auditBreakdown = [
      { category: 'SAST Audit', score: 30, max: 30, note: 'Hadolint & Semgrep passed clean' },
      { category: 'SCA Audit', score: 25, max: 30, note: 'Lodash Prototype Pollution alert' },
      { category: 'Secrets Detection', score: 20, max: 20, note: 'Gitleaks scan passed clean' },
      { category: 'Policy Verification', score: 20, max: 20, note: 'Kyverno validation passes' }
    ];
    state.deployments = [
      { id: 1, status: 'SUCCESS', timestamp: new Date().toISOString() },
      { id: 2, status: 'SUCCESS', timestamp: new Date().toISOString() }
    ];
    state.pods = [
      { name: 'secureflow-frontend-5df4c5', status: 'Running', restarts: 0, cpu: '15m', memory: '42Mi' },
      { name: 'secureflow-backend-8bf2da', status: 'Running', restarts: 0, cpu: '34m', memory: '110Mi' },
      { name: 'secureflow-postgres-9fa3bb', status: 'Running', restarts: 0, cpu: '8m', memory: '190Mi' }
    ];
    state.reports = {
      semgrep: { findings: [] },
      trivy_sca: { findings: [] },
      gitleaks: { leaks: [] },
      trivy_container: { findings: [] },
      sbom: {
        packages: [
          { name: 'express', version: '4.18.2', license: 'MIT', type: 'npm' },
          { name: 'pg', version: '8.11.3', license: 'MIT', type: 'npm' },
          { name: 'sqlite3', version: '5.1.6', license: 'BSD-3-Clause', type: 'npm' }
        ]
      }
    };
    state.incidents = [
      { id: 1, severity: 'CRITICAL', title: 'Critical NPM library prototype pollution CVE', status: 'RESOLVED', description: 'Trivy SCA scan triggered alert: Found lodash@4.17.4 with Prototype Pollution severity critical. Source package lock has been flagged by gate policy.', resolution: 'Upgraded dependencies references to version 4.17.21.' }
    ];
    state.auditLogs = [
      { timestamp: new Date().toISOString(), actor: 'GitHub Actions Runner', action: 'Build Pipeline', resource: 'secureflow-backend:latest', result: 'SUCCESS', severity: 'INFO' },
      { timestamp: new Date().toISOString(), actor: 'Cosign Signer', action: 'Sign Image', resource: 'secureflow-backend:latest', result: 'SUCCESS', severity: 'INFO' }
    ];

    updateUI();
  }
}

// Fetch live telemetry summary
async function fetchTelemetry() {
  try {
    const res = await fetch(`${API_BASE}/api/telemetry`);
    if (res.ok) {
      state.telemetry = await res.json();
      renderCharts();
    }
  } catch (err) {
    // Local fallback metrics for visualization offline
    state.telemetry = [
      { time: '12:00', requests: 4, latency: 42 },
      { time: '12:10', requests: 5, latency: 45 },
      { time: '12:20', requests: 3, latency: 38 },
      { time: '12:30', requests: 8, latency: 52 },
      { time: '12:40', requests: 12, latency: 48 },
      { time: '12:50', requests: 6, latency: 41 },
      { time: '13:00', requests: 9, latency: 45 }
    ];
    renderCharts();
  }
}

// Update DOM elements
function updateUI() {
  document.getElementById('security-badge').innerText = `🔒 DevSecOps Score: ${state.securityScore}/100`;
  document.getElementById('sec-score-val').innerText = state.securityScore;
  
  // Set alert color values based on score
  const scoreVal = document.getElementById('sec-score-val');
  const scoreDesc = document.getElementById('sec-score-desc');
  if (state.securityScore >= 90) {
    scoreVal.className = 'metric-value font-outfit text-green';
    scoreDesc.innerText = 'Secure posture. Compliance guidelines satisfied.';
  } else if (state.securityScore >= 75) {
    scoreVal.className = 'metric-value font-outfit text-yellow';
    scoreDesc.innerText = 'Audits flagged. Security gate warning active.';
  } else {
    scoreVal.className = 'metric-value font-outfit text-red';
    scoreDesc.innerText = 'CRITICAL. Unauthorized secrets or CVEs found.';
  }

  // Set health count
  const activeIncCount = state.incidents.filter(i => i.status === 'OPEN').length;
  document.getElementById('active-incidents-val').innerText = activeIncCount;
  document.getElementById('incidents-desc').innerText = activeIncCount > 0 ? `${activeIncCount} alert(s) requiring response.` : 'Platform running healthy.';
  document.getElementById('active-incidents-val').className = activeIncCount > 0 ? 'metric-value font-outfit text-red' : 'metric-value font-outfit text-green';

  // DORA changes
  const totalDeploys = state.deployments.length;
  const failedDeploys = state.deployments.filter(d => d.status === 'FAILED').length;
  const failureRate = totalDeploys > 0 ? Math.round((failedDeploys / totalDeploys) * 100) : 0;
  document.getElementById('dora-failure-rate').innerText = `${failureRate}%`;

  // Render lists
  renderOverviewBreakdown();
  renderAuditLogs();
  
  if (state.activeTab === 'security') {
    switchScannerView(state.activeScanner);
  } else if (state.activeTab === 'kubernetes') {
    renderKubernetes();
  } else if (state.activeTab === 'demo') {
    renderIncidents();
  }
}

// Render Overview Checklist
function renderOverviewBreakdown() {
  const container = document.getElementById('security-breakdown-list');
  if (!container || !state.auditBreakdown.length) return;

  container.innerHTML = state.auditBreakdown.map(item => {
    const isOk = item.score === item.max;
    return `
      <div class="checklist-item ${isOk ? 'ok' : 'fail'}">
        <div class="item-left">
          <span class="status-dot ${isOk ? 'ok' : 'fail'}"></span>
          <div>
            <span class="item-name">${item.category}</span>
            <span class="item-desc">${item.note}</span>
          </div>
        </div>
        <span class="item-score ${isOk ? 'ok' : 'fail'}">${item.score}/${item.max}</span>
      </div>
    `;
  }).join('');
}

// Render Audit Logs lists
function renderAuditLogs() {
  const container = document.getElementById('audit-trail-terminal');
  const obsContainer = document.getElementById('obs-audit-trail-terminal');
  if (!state.auditLogs.length) return;

  const html = state.auditLogs.map(log => {
    const time = new Date(log.timestamp).toLocaleTimeString();
    let style = 'system';
    if (log.severity === 'WARNING') style = 'warn';
    if (log.severity === 'CRITICAL' || log.result === 'FAILED') style = 'error';
    if (log.result === 'SUCCESS') style = 'success';

    return `<div class="terminal-line ${style}">[${time}] ${log.actor} - ${log.action} : ${log.resource} (${log.result})</div>`;
  }).join('');

  if (container) container.innerHTML = html;
  if (obsContainer) obsContainer.innerHTML = html;
}

// Switch tool views
function switchScannerView(scanner) {
  state.activeScanner = scanner;
  
  const cards = document.querySelectorAll('.tool-card');
  cards.forEach(c => c.classList.remove('active'));
  
  const activeCard = document.getElementById(`card-${scanner}`);
  if (activeCard) activeCard.classList.add('active');

  const titles = {
    semgrep: 'Semgrep SAST Code Scan Report',
    trivy_sca: 'Trivy Software Composition Analysis (SCA) Report',
    gitleaks: 'Gitleaks Secrets Scan Report',
    trivy_container: 'Trivy Container Image Scan Report'
  };
  document.getElementById('scanner-output-title').innerText = titles[scanner];

  const report = state.reports[scanner] || { findings: [] };
  const container = document.getElementById('scanner-findings-list');
  const gate = document.getElementById('scanner-gate-status');

  const count = report.findings?.length || report.leaks?.length || 0;
  gate.innerText = count > 0 ? 'Gate: Failed' : 'Gate: Pass';
  gate.className = count > 0 ? 'badge danger-badge' : 'badge success-badge';

  // Populate list
  if (scanner === 'semgrep') {
    const findings = report.findings || [];
    if (!findings.length) {
      container.innerHTML = `<div class="loading">No source code code-audit issues found. Semgrep SAST PASSED.</div>`;
      return;
    }
    container.innerHTML = findings.map(f => `
      <div class="finding-item high">
        <div class="finding-meta">
          <span>RULE: ${f.rule_id}</span>
          <span>FILE: ${f.path}:${f.line}</span>
        </div>
        <div class="finding-title">SAST Cryptographic / Input Violation</div>
        <div class="finding-desc">${f.message}</div>
        <div class="finding-remediation"><strong>Remediation:</strong> Replace plaintext parameters with sanitized logic.</div>
      </div>
    `).join('');
  } else if (scanner === 'trivy_sca') {
    const findings = report.findings || [];
    if (!findings.length) {
      container.innerHTML = `<div class="loading">No packages vulnerabilities found in package locks.</div>`;
      return;
    }
    container.innerHTML = findings.map(f => `
      <div class="finding-item ${f.severity.toLowerCase()}">
        <div class="finding-meta">
          <span>CVE: ${f.id}</span>
          <span>SEVERITY: ${f.severity}</span>
        </div>
        <div class="finding-title">Dependency Risk - ${f.package} (${f.current_version})</div>
        <div class="finding-desc">Known vulnerability exposes node runtime to exploit vector.</div>
        <div class="finding-remediation"><strong>Remediation:</strong> Upgrade package references to fixed version <code>${f.fixed_version}</code>.</div>
      </div>
    `).join('');
  } else if (scanner === 'gitleaks') {
    const leaks = report.leaks || [];
    if (!leaks.length) {
      container.innerHTML = `<div class="loading">No committed secrets detected in active branch targets.</div>`;
      return;
    }
    container.innerHTML = leaks.map(l => `
      <div class="finding-item critical">
        <div class="finding-meta">
          <span>RULE: ${l.rule}</span>
          <span>FILE: ${l.file}:${l.line}</span>
        </div>
        <div class="finding-title">Hardcoded API credential token commit!</div>
        <div class="finding-desc">Exposure matches signature regex: <code>${l.secret.substring(0, 8)}...[REDACTED]</code></div>
        <div class="finding-remediation"><strong>Remediation:</strong> Revoke exposed credentials, pull tokens out of repository config, and rewrite branch commits history.</div>
      </div>
    `).join('');
  } else if (scanner === 'trivy_container') {
    const findings = report.findings || [];
    if (!findings.length) {
      container.innerHTML = `<div class="loading">No container layer base library exploits found.</div>`;
      return;
    }
    container.innerHTML = findings.map(f => `
      <div class="finding-item ${f.severity.toLowerCase()}">
        <div class="finding-meta">
          <span>CVE: ${f.id}</span>
          <span>SEVERITY: ${f.severity}</span>
        </div>
        <div class="finding-title">Base Layer OS Exploit - ${f.package}</div>
        <div class="finding-remediation"><strong>Remediation:</strong> Rebuild using <code>node:18-alpine</code> minimal base configurations.</div>
      </div>
    `).join('');
  }
}

// Render Software Bill of Materials (SBOM)
function renderSbom() {
  const sbom = state.reports.sbom || {};
  const packages = sbom.packages || [];
  document.getElementById('sbom-meta').innerText = `${packages.length} Packages Catalogued`;

  const rows = document.getElementById('sbom-rows');
  if (!packages.length) {
    rows.innerHTML = `<tr><td colspan="5" class="loading">No dependencies found. Run security scan first.</td></tr>`;
    return;
  }

  state.sbomPackages = packages;
  displaySbomRows(packages);
}

function displaySbomRows(pkgList) {
  const rows = document.getElementById('sbom-rows');
  rows.innerHTML = pkgList.map(p => `
    <tr>
      <td class="font-mono"><strong>${p.name}</strong></td>
      <td>${p.version}</td>
      <td><span class="badge">${p.license || 'MIT'}</span></td>
      <td>${p.type || 'npm'}</td>
      <td><span class="badge success-badge">Low Risk</span></td>
    </tr>
  `).join('');
}

function filterSbom() {
  const query = document.getElementById('sbom-search').value.toLowerCase();
  if (!state.sbomPackages) return;
  const filtered = state.sbomPackages.filter(p => p.name.toLowerCase().includes(query) || (p.license && p.license.toLowerCase().includes(query)));
  displaySbomRows(filtered);
}

// Render Kubernetes
function renderKubernetes() {
  const rows = document.getElementById('k8s-pod-rows');
  if (!rows || !state.pods.length) return;

  rows.innerHTML = state.pods.map(p => {
    let statusClass = 'success-badge';
    if (p.status !== 'Running') statusClass = 'danger-badge';
    const isRoot = p.name.includes('root') || p.name.includes('insecure');
    const secBadge = isRoot ? '<span class="badge danger-badge">privileged / UID 0</span>' : '<span class="badge success-badge">Root Dropped</span>';

    return `
      <tr>
        <td class="font-mono">${p.name}</td>
        <td><span class="badge ${statusClass}">${p.status}</span></td>
        <td>${p.restarts}</td>
        <td>${p.cpu}</td>
        <td>${p.memory}</td>
        <td>${secBadge}</td>
      </tr>
    `;
  }).join('');

  // Policy cards
  const policiesList = document.getElementById('k8s-policies-list');
  const policyReport = state.reports.policies || { passed: 4, failed: 0, violations: [] };
  
  const items = [
    { name: 'disallow-root-containers', desc: 'Enforces runAsNonRoot context in pods spec.', status: 'passed' },
    { name: 'require-resource-limits', desc: 'Verifies memory & CPU request boundaries are set.', status: 'passed' },
    { name: 'disallow-latest-tag', desc: 'Denies deployment of images using :latest tag reference.', status: 'passed' }
  ];

  if (policyReport.failed > 0) {
    policyReport.violations.forEach(v => {
      const match = items.find(i => i.name === v.policy);
      if (match) match.status = 'failed';
    });
  }

  policiesList.innerHTML = items.map(p => `
    <div class="policy-card ${p.status}">
      <div class="header-flex">
        <span class="policy-name font-mono">${p.name}</span>
        <span class="badge ${p.status === 'passed' ? 'success-badge' : 'danger-badge'}">${p.status.toUpperCase()}</span>
      </div>
      <p class="policy-msg">${p.desc}</p>
    </div>
  `).join('');
}

// Render Prometheus charts with live telemetry summary data
function renderCharts() {
  const latencyChart = document.getElementById('latency-chart');
  const requestsChart = document.getElementById('requests-chart');
  if (!latencyChart || !requestsChart || !state.telemetry.length) return;

  const latencies = state.telemetry.map(t => t.latency);
  const requests = state.telemetry.map(t => t.requests);

  const avgLatency = Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length);
  document.getElementById('avg-latency-val').innerText = `${avgLatency}ms`;

  const isFailure = state.incidents.some(i => i.title.includes('Outage') && i.status === 'OPEN');

  // Render Latency
  latencyChart.innerHTML = latencies.map(val => {
    const pct = Math.min((val / 150) * 100, 100);
    const styleClass = isFailure && val > 100 ? 'chart-bar alerting' : 'chart-bar';
    return `<div class="${styleClass}" style="height: ${pct}%;"></div>`;
  }).join('');

  // Render Requests
  requestsChart.innerHTML = requests.map(val => {
    const pct = Math.min((val / 20) * 100, 100);
    return `<div class="chart-bar" style="height: ${pct}%; background: linear-gradient(to top, var(--green), #059669);"></div>`;
  }).join('');
}

// Render Incidents history
function renderIncidents() {
  const container = document.getElementById('incidents-history-list');
  if (!container) return;

  if (state.incidents.length === 0) {
    container.innerHTML = `<div class="loading">No active incidents logged.</div>`;
    return;
  }

  container.innerHTML = state.incidents.map(inc => {
    const isOpen = inc.status === 'OPEN';
    const date = new Date(inc.timestamp).toLocaleTimeString();
    
    return `
      <div class="incident-item ${isOpen ? 'open' : 'resolved'}">
        <div class="incident-header">
          <span class="incident-title text-${isOpen ? 'red' : 'green'}">🚨 [${inc.severity}] ${inc.title}</span>
          <span class="incident-meta">Time: ${date}</span>
        </div>
        <p class="incident-desc">${inc.description}</p>
        
        ${isOpen ? `
          <div style="display:flex; gap:10px; margin-top:12px;">
            <button class="btn btn-primary" style="padding: 4px 8px; font-size:11px;" onclick="remediateDemo('${getScenarioKey(inc.title)}')">
              🔧 Resolve Outage
            </button>
          </div>
        ` : `
          <div class="incident-remediation">
            ✔️ <strong>Resolved:</strong> ${inc.resolution}
          </div>
        `}
      </div>
    `;
  }).join('');
}

function getScenarioKey(title) {
  if (title.includes('vulnerability') || title.includes('CVE')) return 'vulnerability';
  if (title.includes('Credentials') || title.includes('secret')) return 'secret';
  if (title.includes('Policy') || title.includes('Webhook')) return 'policy';
  return 'failure';
}

// Demo Inject and Remediate endpoints connection
async function injectDemo(scenario) {
  try {
    const step2 = document.getElementById(`step-${getDemoPrefix(scenario)}-2`);
    if (step2) step2.className = 'demo-dot active';

    const res = await fetch(`${API_BASE}/api/demo/inject`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario })
    });
    
    if (res.ok) {
      state.demoStatus[scenario] = 2;
      updateDemoStepsIndicator(scenario, 2);
      
      // Toggle button views
      document.getElementById(`btn-inject-${getDemoPrefix(scenario)}`).style.display = 'none';
      document.getElementById(`btn-fix-${getDemoPrefix(scenario)}`).style.display = 'inline-flex';
      
      // Specific telemetry spikes on blackout scenario
      if (scenario === 'failure') {
        state.metrics.latency = [42, 50, 48, 140, 185, 202, 195];
      }

      await fetchData();
      alert(`Chaos Injected! Scenario: ${scenario}. View active incidents in the right panel.`);
    }
  } catch (err) {
    console.error('[DEMO] Injection failed:', err);
  }
}

async function remediateDemo(scenario) {
  try {
    const res = await fetch(`${API_BASE}/api/demo/remediate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario })
    });

    if (res.ok) {
      state.demoStatus[scenario] = 3;
      updateDemoStepsIndicator(scenario, 3);
      
      // Toggle button views
      document.getElementById(`btn-inject-${getDemoPrefix(scenario)}`).style.display = 'inline-flex';
      document.getElementById(`btn-fix-${getDemoPrefix(scenario)}`).style.display = 'none';

      await fetchData();
      alert(`Remediation Applied! Scenario: ${scenario} has been patched.`);
    }
  } catch (err) {
    console.error('[DEMO] Remediation failed:', err);
  }
}

// Helper to resolve prefixes
function getDemoPrefix(scenario) {
  if (scenario === 'vulnerability') return 'vuln';
  if (scenario === 'secret') return 'sec';
  if (scenario === 'policy') return 'pol';
  return 'fail';
}

function updateDemoStepsIndicator(scenario, step) {
  const prefix = getDemoPrefix(scenario);
  const dot1 = document.getElementById(`step-${prefix}-1`);
  const dot2 = document.getElementById(`step-${prefix}-2`);
  const dot3 = document.getElementById(`step-${prefix}-3`);

  if (step === 2) {
    dot1.className = 'demo-dot passed';
    dot2.className = 'demo-dot failed';
    dot3.className = 'demo-dot';
  } else if (step === 3) {
    dot1.className = 'demo-dot passed';
    dot2.className = 'demo-dot passed';
    dot3.className = 'demo-dot passed';
  } else {
    dot1.className = 'demo-dot active';
    dot2.className = 'demo-dot';
    dot3.className = 'demo-dot';
  }
}

// Manual pipeline trigger
async function triggerManualScan() {
  const badge = document.getElementById('security-badge');
  badge.innerText = '🔒 Scanning...';
  
  try {
    await fetch(`${API_BASE}/api/security`);
    setTimeout(async () => {
      await fetchData();
      alert('Manual Security Pipeline completed. Reports reloaded.');
    }, 1000);
  } catch (err) {
    console.error(err);
  }
}

// Inspect Component Maps
function inspectArchComponent(id) {
  const details = {
    sast: {
      name: 'Semgrep SAST Code Analyzer',
      tech: 'Semgrep OSS Engine',
      role: 'Static Application Security Testing matches dangerous code constructs (SQLi, unsafe crypto) on commits.',
      failure: 'Compromised developer IDE pushes unvetted logic directly to main branches.'
    },
    sca: {
      name: 'Trivy Software Composition Analysis (SCA)',
      tech: 'Trivy CLI',
      role: 'Checks dependencies against matching CVE lists.',
      failure: 'Vulnerable packages containing Prototype Pollution load at runtime.'
    },
    secrets: {
      name: 'Gitleaks Secrets Auditing',
      tech: 'Gitleaks CLI',
      role: 'Checks for hardcoded API access credentials and keys.',
      failure: 'Plaintext secret keys leakage in production scripts.'
    },
    sbom: {
      name: 'Syft Software Bill of Materials',
      tech: 'Syft cataloger',
      role: 'Generates package list catalog for compliance checks.',
      failure: 'Unchecked transitive vulnerabilities load silently.'
    },
    cosign: {
      name: 'Cosign Image Signatures',
      tech: 'Cosign key pair',
      role: 'Signs built image digests verifying source origin authenticity.',
      failure: 'Malicious third party images inject and execute in pod specs.'
    },
    kyverno: {
      name: 'Kyverno Policy Validation',
      tech: 'Kyverno engine webhook',
      role: 'Blocks pods attempting privileged contexts or runAsNonRoot: false.',
      failure: 'Compromised container escalates to system root node access.'
    }
  };

  const c = details[id];
  const container = document.getElementById('arch-details-panel');
  container.innerHTML = `
    <h3>Component: ${c.name}</h3>
    <div class="arch-details-box">
      <p><strong>Integrated Technology:</strong> ${c.tech}</p><br>
      <p><strong>Primary Role:</strong> ${c.role}</p><br>
      <p><strong>Common Failure Mode:</strong> <span class="text-red">${c.failure}</span></p>
    </div>
  `;
}

// Docs rendering
const docContents = {
  'doc-install': `### Installation & Execution Guide

To operate the DevSecOps ecosystem platform locally on Windows/WSL2, execute:

1. **Initialize node dependencies**:
   \`\`\`bash
   npm install --prefix app/backend
   \`\`\`

2. **Trigger Security scanning suite**:
   \`\`\`bash
   node scripts/security-scan.js
   \`\`\`

3. **Start local Express server daemon**:
   \`\`\`bash
   node app/backend/index.js
   \`\`\`

Open browser URL \`http://localhost:5000\` to view telemetry and audits.`,
  'doc-scenarios': `### Chaos & Outage Scenarios Reference

The system provides 4 interactive simulation tracks:

1. **Vulnerability Gate**: Appends \`lodash@4.17.4\` (CVE-2020-8203) to dependencies. The Trivy SCA scan blocks pipeline compilation.
2. **Secrets Leak**: Commits a mock AWS Secret key in \`db.js\]. Gitleaks scanner drops pipeline compilation.
3. **Kyverno Webhook Violation**: Sets \`runAsNonRoot: false\` in the deployment specs. Kubernetes admission controller blocks workload schedule.
4. **API Service Outage**: Shuts down PostgreSQL pools, causing latencies to spike and triggering Prometheus AlertManager rules.`,
  'doc-production': `### AWS RDS Database Specifications

In production configurations:
- **RDS Subnet group**: Isolated inside Private subnets.
- **KMS Storage Encryption**: Enabled using customer-managed keys (CMK).
- **High Availability**: Multi-AZ replicas provide failover transitions.
- **Ingress Security Groups**: Strictly limits TCP 5432 ingress solely to EKS Node security groups.`
};

function switchDocTab(docId) {
  state.activeDoc = docId;
  const tabs = document.querySelectorAll('.guide-tab');
  tabs.forEach(t => {
    if (t.getAttribute('onclick').includes(docId)) {
      t.classList.add('active');
    } else {
      t.classList.remove('active');
    }
  });

  const box = document.getElementById('doc-content-box');
  box.innerHTML = docContents[docId].replace(/\n/g, '<br>').replace(/`([^`]+)`/g, '<code class="font-mono" style="background:rgba(255,255,255,0.03); padding:2px 4px; border-radius:3px; font-size:12px;">$1</code>');
}

// Inspect individual stages from Pipelines Tab
function inspectPipelineStage(stage) {
  const details = {
    checkout: {
      title: 'Checkout & Code Source Control',
      purpose: 'Secures access logs and verifies git commit authorization signatures.',
      tech: ['Git', 'SSH', 'GPG Signing'],
      secVal: 'Ensures code comes from verified developers, preventing unauthorized malicious commits.',
      implementation: 'GitHub repository settings require signed commits. Deploy keys used in CI have read-only access.'
    },
    sast: {
      title: 'Semgrep Static Analysis (SAST)',
      purpose: 'Scans source files for syntax patterns representing dangerous code vulnerabilities.',
      tech: ['Semgrep OSS', 'Hadolint'],
      secVal: 'Identifies flaws (like SQL Injection, XSS, unescaped queries) early in the IDE or commit hooks.',
      implementation: 'Runs on every PR branch. Denies merge if critical rules fail code review thresholds.'
    },
    sca: {
      title: 'Trivy Dependency Analysis (SCA)',
      purpose: 'Audits open-source node modules and imports for matching database CVE lists.',
      tech: ['Trivy CLI', 'Snyk'],
      secVal: 'Blocks supply chain attacks where clean code loads exploit-heavy external dependencies.',
      implementation: 'Configured with threshold gates. Retains software dependency lock integrity.'
    },
    secrets: {
      title: 'Gitleaks Credentials Auditing',
      purpose: 'Uses regex patterns and entropy rules to prevent keys being pushed to repository archives.',
      tech: ['Gitleaks', 'Trufflehog'],
      secVal: 'Blocks API tokens, SSH keys, or DB logins from leaking into public Git repositories.',
      implementation: 'Fails pipeline if matches found. Code history rewritten immediately if keys detected.'
    },
    build: {
      title: 'Containerization Image Build',
      purpose: 'Packages application code with minimal OS dependencies into standard Docker images.',
      tech: ['Docker Engine', 'Kaniko'],
      secVal: 'Standardizes runtime configurations, eliminating system-level drift vulnerabilities.',
      implementation: 'Base images restricted to official Alpine/distroless. Multistage build discards compilation assets.'
    },
    cscan: {
      title: 'Trivy Base OS Vulnerability Scan',
      purpose: 'Audits the built Docker container layer dependencies.',
      tech: ['Trivy Image Scan'],
      secVal: 'Identifies Linux library exploits inside alpine layers before publishing.',
      implementation: 'Blocks deployment when vulnerabilities with active exploits are discovered.'
    },
    sbom: {
      title: 'Syft SBOM Cataloging',
      purpose: 'Generates structured packages bill list of packages (CycloneDX format).',
      tech: ['Syft CLI', 'Grype'],
      secVal: 'Provides dynamic tracking of third-party software imports for security audit validation.',
      implementation: 'Produces JSON metadata saved as build artifacts for compliance checks.'
    },
    sign: {
      title: 'Cosign Cryptographic Image Signing',
      purpose: 'Signs the generated image digest with developer private keys.',
      tech: ['Cosign', 'AWS KMS'],
      secVal: 'Ensures container deployment integrity, blocking unauthorized third-party images.',
      implementation: 'Admission controller verifies signature on cluster load, validating origin source.'
    },
    k8s: {
      title: 'Kubernetes Admission & Runtimes',
      purpose: 'Deploys workloads under tight resource allocations and security profiles.',
      tech: ['Kubernetes API', 'Kyverno Admission Controller'],
      secVal: 'Enforces principle of least privilege, preventing containers from running as root.',
      implementation: 'Applies NetworkPolicies to restrict pod-to-pod routing. Kyverno blocks root deployments.'
    }
  };

  const data = details[stage];
  const card = document.getElementById('pipeline-inspection-card');
  if (!card) return;

  card.innerHTML = `
    <div class="header-flex">
      <h3>${data.title}</h3>
      <span class="badge success-badge">Security Injected</span>
    </div>
    <div class="split-layout" style="margin-top:10px;">
      <div style="flex:1;">
        <p><strong>Primary Purpose:</strong> ${data.purpose}</p><br>
        <p><strong>Security Value:</strong> ${data.secVal}</p><br>
        <p><strong>Integrated Technologies:</strong></p>
        <div class="tool-tag-list">
          ${data.tech.map(t => `<span class="tool-tag highlight">${t}</span>`).join('')}
        </div>
      </div>
      <div style="flex:1; border-left: 1px solid var(--border-color); padding-left: 20px;">
        <p><strong>Production Implementation:</strong></p>
        <p style="font-size:13px; color: var(--text-secondary); margin-top:8px; line-height:1.5;">${data.implementation}</p>
      </div>
    </div>
  `;
}

// AI Bedrock Advisor Chat
function applyPrompt(text) {
  document.getElementById('ai-chat-input').value = text;
}

function handleAiSubmit(event) {
  if (event.key === 'Enter') {
    submitAiQuery();
  }
}

async function submitAiQuery() {
  const input = document.getElementById('ai-chat-input');
  const queryText = input.value.trim();
  if (!queryText) return;

  const chatBox = document.getElementById('ai-chat-box');
  
  // User bubble
  const userMsg = document.createElement('div');
  userMsg.className = 'chat-message user';
  userMsg.innerHTML = `<div class="message-sender">User</div><div class="message-content">${queryText}</div>`;
  chatBox.appendChild(userMsg);
  input.value = '';
  chatBox.scrollTop = chatBox.scrollHeight;

  // Bot loading
  const botMsg = document.createElement('div');
  botMsg.className = 'chat-message bot';
  botMsg.innerHTML = `<div class="message-sender">🛡️ SecureFlow Agent</div><div class="message-content"><em>AI advisor preparing analysis recommendation...</em></div>`;
  chatBox.appendChild(botMsg);
  chatBox.scrollTop = chatBox.scrollHeight;

  const activeInc = state.incidents.filter(i => i.status === 'OPEN');
  
  setTimeout(() => {
    let responseText = '';
    
    if (queryText.toLowerCase().includes('fail') || queryText.toLowerCase().includes('pipeline')) {
      if (activeInc.length > 0) {
        responseText = `Based on the latest automated report logs, the deployment pipeline is failing because of an active incident: **"${activeInc[0].title}"** in component **${activeInc[0].component}**. 
        <br><br>
        <strong>Recommendation details:</strong>
        <br>1. Trigger the automated remediation action inside the Incidents tab.
        <br>2. For dependency issues, review the Trivy scan outputs and upgrade packages as suggested.
        <br>3. For policy rejections, verify the resource constraints inside the Kubernetes deployment manifests.
        <br><br>
        <em>AI recommendation — engineering verification required.</em>`;
      } else {
        responseText = `The deployment pipeline is currently **passing** successfully. 
        All security gates (Semgrep, Gitleaks, Trivy, Kyverno) report compliant status (Security Score: ${state.securityScore}/100).
        <br><br>
        <em>AI recommendation — engineering verification required.</em>`;
      }
    } else if (queryText.toLowerCase().includes('vulnerability') || queryText.toLowerCase().includes('trivy')) {
      responseText = `Trivy Dependency Scanner is auditing npm packages in <code>app/backend/package.json</code>. 
      <br><br>
      Common vulnerabilities found in this stack (like Lodash prototype pollution CVEs) occur when input keys are improperly merged into objects.
      <br><br>
      <strong>Remediation Steps:</strong>
      <br>1. Upgrade the package dependencies list to version 4.17.21 or later.
      <br>2. Run <code>npm audit fix</code> to update transitive dependencies.
      <br>3. Avoid using unchecked Object merges in JavaScript codebase helper scripts.
      <br><br>
      <em>AI recommendation — engineering verification required.</em>`;
    } else if (queryText.toLowerCase().includes('kyverno') || queryText.toLowerCase().includes('policy')) {
      responseText = `Kyverno Policy validation runs as an Admission Webhook. It blocks pods that fail checks before they reach etcd.
      <br><br>
      Your configurations enforce rules:
      <br>1. <code>disallow-root-containers</code> (blocks containers running with UID 0).
      <br>2. <code>require-resource-limits</code> (prevents memory exhaustion).
      <br><br>
      <strong>Fix:</strong> Update the Pod spec inside the manifest to configure <code>securityContext.runAsNonRoot: true</code>.
      <br><br>
      <em>AI recommendation — engineering verification required.</em>`;
    } else if (queryText.toLowerCase().includes('postgres') || queryText.toLowerCase().includes('database') || queryText.toLowerCase().includes('rds')) {
      responseText = `The production AWS architecture specifies a Multi-AZ **Amazon RDS PostgreSQL** instance.
      <br><br>
      <strong>Best Practice Security Controls deployed:</strong>
      <br>1. **Data at Rest:** Encrypted via AWS KMS customer managed key (CMK).
      <br>2. **Network Isolation:** Positioned inside private subnets; security group ingress permits access ONLY from EKS worker node security groups on port 5432.
      <br>3. **High Availability:** Active replication to a secondary Availability Zone provides automated failover support.
      <br>4. **Authentication:** Configured to use IAM Database Authentication rather than static master credentials.
      <br><br>
      <em>AI recommendation — engineering verification required.</em>`;
    } else {
      responseText = `I have received your request: "${queryText}". 
      Based on the secure DevOps model, here are general guidelines:
      <br>1. Keep Docker base layers small and clean (alpine or distroless).
      <br>2. Inject environment keys via Kubernetes secrets, backed by vault providers.
      <br>3. Verify all infrastructure configurations via Terraform validation checks before provisioning.
      <br><br>
      <em>AI recommendation — engineering verification required.</em>`;
    }

    botMsg.querySelector('.message-content').innerHTML = responseText;
    chatBox.scrollTop = chatBox.scrollHeight;
  }, 1000);
}
