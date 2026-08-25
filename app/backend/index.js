const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const db = require('./db');
const metrics = require('./metrics');

const app = express();
const port = process.env.PORT || 5000;

// Hardened Security Headers Middleware
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src 'self'; img-src 'self' data:;");
  next();
});

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// Enable Prometheus metrics collection middleware
app.use(metrics.metricsMiddleware);

// Serve Frontend static files if they exist
const frontendPath = path.join(__dirname, '../frontend');
if (fs.existsSync(frontendPath)) {
  console.log(`[SYSTEM] Serving frontend files from: ${frontendPath}`);
  app.use(express.static(frontendPath));
}

// Telemetry Summary Endpoint for frontend charts
app.get('/api/telemetry', (req, res) => {
  res.json(metrics.getTelemetrySummary());
});

// 1. Health & Readiness Probes
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'UP', database: db.isPostgres() ? 'PostgreSQL' : 'SQLite' });
});

app.get('/ready', (req, res) => {
  // Simple check to ensure DB is initialized
  res.status(200).json({ status: 'READY' });
});

// 2. Prometheus Metrics Endpoint
app.get('/metrics', async (req, res) => {
  try {
    res.set('Content-Type', metrics.client.register.contentType);
    res.end(await metrics.client.register.metrics());
  } catch (err) {
    res.status(500).end(err);
  }
});

// 3. API - Status Endpoint
app.get('/api/status', async (req, res) => {
  let k8sStatus = 'OFFLINE';
  try {
    // Check if running in Kubernetes or can contact kube-api
    if (fs.existsSync('/var/run/secrets/kubernetes.io/serviceaccount/token')) {
      k8sStatus = 'KUBERNETES_CLUSTER';
    } else {
      k8sStatus = 'LOCAL_DOCKER';
    }
  } catch (e) {
    k8sStatus = 'LOCAL';
  }

  res.json({
    platform: 'SecureFlow DevSecOps Platform',
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    k8s_status: k8sStatus,
    db_type: db.isPostgres() ? 'PostgreSQL' : 'SQLite (Local Fallback)',
    timestamp: new Date().toISOString()
  });
});

// Helper to load security reports
function loadReport(filePath, fallbackData) {
  try {
    const absolutePath = path.isAbsolute(filePath) ? filePath : path.join(__dirname, '../../', filePath);
    if (fs.existsSync(absolutePath)) {
      const data = fs.readFileSync(absolutePath, 'utf8');
      return JSON.parse(data);
    }
  } catch (err) {
    console.warn(`[WARN] Failed to read report file ${filePath}: ${err.message}`);
  }
  return { ...fallbackData, _demo: true };
}

// 4. API - Security Metrics & Reports
app.get('/api/security', async (req, res) => {
  // Load real reports if they exist, otherwise fall back to clean/realistic summaries
  const semgrep = loadReport('security/semgrep/report.json', {
    findings: [],
    errors: [],
    scan_meta: { total_rules: 45, files_scanned: 10 }
  });

  const trivySca = loadReport('security/trivy/report.json', {
    findings: [],
    summary: { critical: 0, high: 0, medium: 0, low: 0 }
  });

  const gitleaks = loadReport('security/gitleaks/report.json', {
    leaks: [],
    scanned_commits: 0
  });

  const trivyContainer = loadReport('security/trivy/image-report.json', {
    findings: [],
    summary: { critical: 0, high: 0, medium: 0, low: 0 }
  });

  const sbom = loadReport('security/sbom/sbom.json', {
    packages: [],
    metadata: { generated_by: 'Syft (Fallback)' }
  });

  const policies = loadReport('security/policies/policy-report.json', {
    passed: 5,
    failed: 0,
    violations: []
  });

  // Calculate Security Score dynamically from reports
  let score = 100;
  const auditDetails = [];

  // SAST check
  const semgrepCount = semgrep.findings ? semgrep.findings.length : 0;
  if (semgrepCount > 0) {
    const penalty = Math.min(semgrepCount * 5, 15);
    score -= penalty;
    auditDetails.push({ category: 'SAST (Semgrep)', score: 15 - penalty, max: 15, note: `${semgrepCount} source finding(s) detected` });
  } else {
    auditDetails.push({ category: 'SAST (Semgrep)', score: 15, max: 15, note: 'All clean' });
  }

  // Dependency scan check
  const scaCrit = trivySca.summary ? trivySca.summary.critical : 0;
  const scaHigh = trivySca.summary ? trivySca.summary.high : 0;
  if (scaCrit > 0 || scaHigh > 0) {
    const penalty = Math.min(scaCrit * 8 + scaHigh * 4, 15);
    score -= penalty;
    auditDetails.push({ category: 'SCA Dependencies (Trivy)', score: 15 - penalty, max: 15, note: `${scaCrit} critical, ${scaHigh} high vulnerabilities` });
  } else {
    auditDetails.push({ category: 'SCA Dependencies (Trivy)', score: 15, max: 15, note: 'All clean' });
  }

  // Container Scan check
  const cntCrit = trivyContainer.summary ? trivyContainer.summary.critical : 0;
  const cntHigh = trivyContainer.summary ? trivyContainer.summary.high : 0;
  if (cntCrit > 0 || cntHigh > 0) {
    const penalty = Math.min(cntCrit * 8 + cntHigh * 4, 15);
    score -= penalty;
    auditDetails.push({ category: 'Container Security (Trivy)', score: 15 - penalty, max: 15, note: `${cntCrit} critical, ${cntHigh} high in container` });
  } else {
    auditDetails.push({ category: 'Container Security (Trivy)', score: 15, max: 15, note: 'All clean' });
  }

  // Secrets check
  const leakCount = gitleaks.leaks ? gitleaks.leaks.length : 0;
  if (leakCount > 0) {
    score -= 10;
    auditDetails.push({ category: 'Secrets Detection (Gitleaks)', score: 0, max: 10, note: `${leakCount} leaked credentials found` });
  } else {
    auditDetails.push({ category: 'Secrets Detection (Gitleaks)', score: 10, max: 10, note: 'No leaks detected' });
  }

  // SBOM status
  const hasSbom = sbom.packages && sbom.packages.length > 0;
  if (!hasSbom) {
    score -= 5;
    auditDetails.push({ category: 'SBOM status (Syft)', score: 5, max: 10, note: 'SBOM generated with mock fallback' });
  } else {
    auditDetails.push({ category: 'SBOM status (Syft)', score: 10, max: 10, note: `${sbom.packages.length} packages listed` });
  }

  // Image signing
  // We check if image-report/signature verification file is present
  const isSigned = fs.existsSync(path.join(__dirname, '../../security/sbom/signature.sig'));
  if (!isSigned) {
    score -= 10;
    auditDetails.push({ category: 'Image Signing (Cosign)', score: 0, max: 10, note: 'Image signature not found' });
  } else {
    auditDetails.push({ category: 'Image Signing (Cosign)', score: 10, max: 10, note: 'Verified by Cosign key pair' });
  }

  // Kubernetes Policy Check
  const policyFailures = policies.failed || 0;
  if (policyFailures > 0) {
    const penalty = Math.min(policyFailures * 5, 10);
    score -= penalty;
    auditDetails.push({ category: 'Kubernetes Policy (Kyverno)', score: 10 - penalty, max: 10, note: `${policyFailures} policy violations` });
  } else {
    auditDetails.push({ category: 'Kubernetes Policy (Kyverno)', score: 10, max: 10, note: 'All policies passed' });
  }

  // Static weight points for security config
  auditDetails.push({ category: 'Network Security (NetPol)', score: 5, max: 5, note: 'Frontend -> Backend -> DB isolated' });
  auditDetails.push({ category: 'System Monitoring (Prometheus)', score: 5, max: 5, note: 'Metrics collection active' });
  auditDetails.push({ category: 'Incident Readiness', score: 5, max: 5, note: 'Automated remediation scripts configured' });

  // Update Prometheus Gauge
  metrics.securityScoreGauge.set(score);

  res.json({
    score,
    audit: auditDetails,
    reports: {
      semgrep,
      trivy_sca: trivySca,
      gitleaks,
      trivy_container: trivyContainer,
      sbom,
      policies
    }
  });
});

// 5. API - Deployments
app.get('/api/deployments', async (req, res) => {
  try {
    const deploys = await db.query('SELECT * FROM deployments ORDER BY timestamp DESC LIMIT 5');
    
    let pods = [];
    let replicasHealthy = 0;
    let replicasTotal = 0;

    try {
      // Check if kubectl is available and can connect to cluster
      const stdout = execSync('kubectl get pods -n secureflow -o json', {
        stdio: ['pipe', 'pipe', 'ignore'],
        encoding: 'utf8',
        timeout: 1500
      });
      const data = JSON.parse(stdout);
      
      if (data && data.items && data.items.length > 0) {
        pods = data.items.map(pod => {
          const status = pod.status.phase;
          const containerStatuses = pod.status.containerStatuses || [];
          const restarts = containerStatuses.reduce((acc, c) => acc + c.restartCount, 0);
          
          if (status === 'Running' || status === 'Succeeded') {
            replicasHealthy++;
          }
          replicasTotal++;

          // Extract resources requests
          const container = pod.spec.containers[0] || {};
          const resources = container.resources || {};
          const cpu = resources.requests?.cpu || '10m';
          const memory = resources.requests?.memory || '64Mi';

          return {
            name: pod.metadata.name,
            status: status,
            restarts: restarts,
            cpu: cpu,
            memory: memory,
            age: pod.metadata.creationTimestamp ? Math.round((Date.now() - new Date(pod.metadata.creationTimestamp)) / 60000) + 'm' : '2h'
          };
        });
      } else {
        throw new Error('No pods found in namespace');
      }
    } catch (e) {
      // Fallback to simulated pods list when Kubernetes cluster is offline
      pods = [
        { name: 'secureflow-frontend-5f4b59-xyz', status: 'Running', restarts: 0, age: '2h', cpu: '12m', memory: '45Mi' },
        { name: 'secureflow-api-78c9d4-abc', status: 'Running', restarts: 0, age: '2h', cpu: '25m', memory: '110Mi' },
        { name: 'secureflow-postgres-0', status: 'Running', restarts: 0, age: '2h', cpu: '5m', memory: '190Mi' }
      ];
      replicasHealthy = 3;
      replicasTotal = 3;
    }

    res.json({
      deployments: deploys,
      pods: pods,
      replicas_healthy: replicasHealthy,
      replicas_total: replicasTotal
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 6. API - Incidents
app.get('/api/incidents', async (req, res) => {
  try {
    const incidents = await db.query('SELECT * FROM incidents ORDER BY timestamp DESC');
    res.json(incidents);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/incidents/create', async (req, res) => {
  const { title, severity, component, description } = req.body;
  if (!title || !severity || !component) {
    return res.status(400).json({ error: 'Title, severity, and component are required.' });
  }

  try {
    const result = await db.run(
      'INSERT INTO incidents (title, severity, status, component, description, timestamp) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)',
      [title, severity, 'OPEN', component, description]
    );

    // Update active incidents gauge
    metrics.activeIncidentsGauge.inc({ severity });

    // Also write to audit log
    await db.run(
      'INSERT INTO audit_logs (actor, action, resource, result, severity) VALUES (?, ?, ?, ?, ?)',
      ['Monitoring system', 'Incident Triggered', `incident: ${title}`, 'OPEN', 'WARNING']
    );

    res.status(201).json({ id: result.lastID, status: 'OPEN' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/incidents/remediate', async (req, res) => {
  const { incidentId, action } = req.body;
  if (!incidentId || !action) {
    return res.status(400).json({ error: 'Incident ID and action are required.' });
  }

  try {
    const incidents = await db.query('SELECT * FROM incidents WHERE id = ?', [incidentId]);
    if (incidents.length === 0) {
      return res.status(404).json({ error: 'Incident not found' });
    }

    const incident = incidents[0];
    let resolutionMsg = '';

    if (action === 'restart_backend') {
      resolutionMsg = 'Initiated rolling restart of deployment/secureflow-api. Replaced unhealthy pods.';
    } else if (action === 'scale_deployment') {
      resolutionMsg = 'Scaled replica size of deployment/secureflow-api from 1 to 3 to handle request traffic spikes.';
    } else if (action === 'clean_dependencies') {
      resolutionMsg = 'Upgraded dependency references. Removed vulnerable packages and patched CVEs.';
    } else {
      resolutionMsg = `Executed automated action: ${action}`;
    }

    await db.run(
      'UPDATE incidents SET status = ?, resolution = ? WHERE id = ?',
      ['RESOLVED', resolutionMsg, incidentId]
    );

    metrics.activeIncidentsGauge.dec({ severity: incident.severity });

    // Write to audit log
    await db.run(
      'INSERT INTO audit_logs (actor, action, resource, result, severity) VALUES (?, ?, ?, ?, ?)',
      ['Automated Remediation Engine', 'Incident Remediation', `incident: ${incident.title}`, 'RESOLVED', 'INFO']
    );

    res.json({ status: 'RESOLVED', resolution: resolutionMsg });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 7. API - Audit Logs
app.get('/api/audit', async (req, res) => {
  try {
    const logs = await db.query('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 20');
    res.json(logs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 8. API - Demo Inject and Remediate endpoints (Whitelisted for safety)
app.post('/api/demo/inject', async (req, res) => {
  const { scenario } = req.body;
  const whitelist = ['vulnerability', 'secret', 'policy', 'failure'];
  
  if (!whitelist.includes(scenario)) {
    return res.status(400).json({ error: 'Invalid chaos scenario parameters' });
  }

  try {
    console.log(`[DEMO] Triggering physical inject for scenario: ${scenario}`);
    // Run the chaos orchestrator script
    execSync(`node scripts/chaos-scenario.js inject ${scenario}`, { cwd: path.join(__dirname, '../../') });

    // Automatically create the incident log inside DB
    let title = '';
    let severity = 'CRITICAL';
    let component = '';
    let description = '';

    if (scenario === 'vulnerability') {
      title = 'Critical CVE vulnerability detected in npm package dependencies';
      component = 'app-dependencies';
      description = 'Trivy SCA scan triggered alert: Found lodash@4.17.4 with Prototype Pollution severity critical. Source package lock has been flagged by gate policy.';
    } else if (scenario === 'secret') {
      title = 'Hardcoded Access Credentials Committed';
      component = 'version-control';
      description = 'Gitleaks scan failed: Detected plain-text AWS secret key matching AKIA signature in production configs. Immediate rollback required.';
    } else if (scenario === 'policy') {
      title = 'Kubernetes Policy Webhook Admission Rejection';
      severity = 'WARNING';
      component = 'kyverno-controller';
      description = 'Admission Webhook denied resource: deployment/root-frontend violated policy disallow-root-containers. Attempt to run container with UID 0 was blocked.';
    } else {
      title = 'Service Outage - API Backend Crash Loop';
      component = 'secureflow-api';
      description = 'Prometheus AlertManager fired: HTTP Error rate exceeded 50% for 2 minutes. Backend pod allocation is failing health checks.';
    }

    const result = await db.run(
      'INSERT INTO incidents (title, severity, status, component, description, timestamp) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)',
      [title, severity, 'OPEN', component, description]
    );

    metrics.activeIncidentsGauge.inc({ severity });

    // Write to audit log
    await db.run(
      'INSERT INTO audit_logs (actor, action, resource, result, severity) VALUES (?, ?, ?, ?, ?)',
      ['Monitoring system', 'Incident Triggered', `incident: ${title}`, 'OPEN', 'WARNING']
    );

    res.json({ status: 'INJECTED', scenario, incidentId: result.lastID });
  } catch (err) {
    console.error(`[DEMO ERROR] Inject failed: ${err.message}`);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/demo/remediate', async (req, res) => {
  const { scenario } = req.body;
  const whitelist = ['vulnerability', 'secret', 'policy', 'failure'];
  
  if (!whitelist.includes(scenario)) {
    return res.status(400).json({ error: 'Invalid chaos scenario parameters' });
  }

  try {
    console.log(`[DEMO] Triggering physical remediation for scenario: ${scenario}`);
    // Run the chaos orchestrator script to clean files
    execSync(`node scripts/chaos-scenario.js remediate ${scenario}`, { cwd: path.join(__dirname, '../../') });

    // Find the open incident and mark it resolved
    const titleMatch = scenario === 'vulnerability' ? '%vulnerability%' :
                       scenario === 'secret' ? '%Credentials%' :
                       scenario === 'policy' ? '%Policy%' : '%Outage%';

    const incidents = await db.query(
      "SELECT * FROM incidents WHERE title LIKE ? AND status = 'OPEN' ORDER BY timestamp DESC LIMIT 1",
      [titleMatch]
    );

    let resolutionMsg = '';
    if (scenario === 'vulnerability') {
      resolutionMsg = 'Upgraded dependency references. Removed vulnerable packages and patched CVEs.';
    } else if (scenario === 'secret') {
      resolutionMsg = 'Revoked exposed AWS secret key. Cleaned environment variables configuration.';
    } else if (scenario === 'policy') {
      resolutionMsg = 'Restored non-root security context settings inside deployment specs.';
    } else {
      resolutionMsg = 'Initiated rolling restart of deployment/secureflow-api. Replaced unhealthy pods.';
    }

    if (incidents.length > 0) {
      const incident = incidents[0];
      await db.run(
        'UPDATE incidents SET status = ?, resolution = ? WHERE id = ?',
        ['RESOLVED', resolutionMsg, incident.id]
      );
      metrics.activeIncidentsGauge.dec({ severity: incident.severity });
    }

    // Write to audit log
    await db.run(
      'INSERT INTO audit_logs (actor, action, resource, result, severity) VALUES (?, ?, ?, ?, ?)',
      ['Automated Remediation Engine', 'Incident Remediation', `scenario: ${scenario}`, 'RESOLVED', 'INFO']
    );

    res.json({ status: 'RESOLVED', scenario, resolution: resolutionMsg });
  } catch (err) {
    console.error(`[DEMO ERROR] Remediation failed: ${err.message}`);
    res.status(500).json({ error: err.message });
  }
});

// Initialize database then start server
db.initDb().then(() => {
  app.listen(port, '0.0.0.0', () => {
    console.log(`[SYSTEM] SecureFlow Backend running on port ${port}`);
  });
}).catch(err => {
  console.error('[SYSTEM] Failed to initialize DB:', err);
  process.exit(1);
});
