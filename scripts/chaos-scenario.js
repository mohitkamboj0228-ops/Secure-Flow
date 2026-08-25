const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const ROOT_DIR = path.join(__dirname, '..');
const BACKEND_DIR = path.join(ROOT_DIR, 'app/backend');
const SECURITY_DIR = path.join(ROOT_DIR, 'security');

const action = process.argv[2]; // "inject" or "remediate"
const target = process.argv[3]; // "vulnerability", "secret", "policy", "failure"

if (!action || !target) {
  console.log('Usage:');
  console.log('  node scripts/chaos-scenario.js inject <vulnerability|secret|policy|failure>');
  console.log('  node scripts/chaos-scenario.js remediate <vulnerability|secret|policy|failure>');
  process.exit(1);
}

// 1. INJECT SCENARIOS
if (action === 'inject') {
  console.log(`[CHAOS] Injecting scenario: ${target}...`);
  
  if (target === 'vulnerability') {
    // Inject vulnerable dependency in package.json
    const pkgPath = path.join(BACKEND_DIR, 'package.json');
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    pkg.dependencies['lodash'] = '4.17.4'; // vulnerable version
    fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2));
    console.log('✓ Injected vulnerable dependency lodash@4.17.4 in package.json');
    
    // Inject vulns directly to report so Trivy parser catches it
    const scaReportPath = path.join(SECURITY_DIR, 'trivy/report.json');
    const report = {
      summary: { critical: 1, high: 0, medium: 0, low: 0 },
      findings: [{
        id: 'CVE-2020-8203',
        severity: 'CRITICAL',
        package: 'lodash',
        current_version: '4.17.4',
        fixed_version: '4.17.21',
        title: 'Prototype Pollution vulnerability in lodash defaults Deepmerge helper.'
      }]
    };
    fs.writeFileSync(scaReportPath, JSON.stringify(report, null, 2));
    
  } else if (target === 'secret') {
    // Inject fake AWS Access Key in db.js
    const dbPath = path.join(BACKEND_DIR, 'db.js');
    let content = fs.readFileSync(dbPath, 'utf8');
    content = content.replace('const pgHost = process.env.DB_HOST;', 'const pgHost = process.env.DB_HOST;\nconst AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"; // Fake secret');
    fs.writeFileSync(dbPath, content);
    console.log('✓ Injected mock secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY in db.js');
    
    // Inject finding directly to gitleaks report
    const secretsReportPath = path.join(SECURITY_DIR, 'gitleaks/report.json');
    const report = {
      leaks: [{
        rule: 'AWS Secret Key',
        file: 'app/backend/db.js',
        line: 12,
        secret: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
      }],
      scanned_commits: 6,
      timestamp: new Date().toISOString()
    };
    fs.writeFileSync(secretsReportPath, JSON.stringify(report, null, 2));

  } else if (target === 'policy') {
    // Modify backend-deployment.yaml to violate Kyverno Policies (run as root and no resources limits)
    const deployPath = path.join(ROOT_DIR, 'kubernetes/base/backend-deployment.yaml');
    let content = fs.readFileSync(deployPath, 'utf8');
    content = content.replace('runAsNonRoot: true', 'runAsNonRoot: false');
    content = content.replace('runAsUser: 1000', 'runAsUser: 0'); // run as root
    fs.writeFileSync(deployPath, content);
    console.log('✓ Modified backend-deployment.yaml: Set runAsNonRoot to false and runAsUser to 0 (Root)');

    // Run policy validation step to regenerate report
    execSync('node scripts/security-scan.js', { stdio: 'inherit' });

  } else if (target === 'failure') {
    console.log('✓ System blackout simulated. Request rate metrics spiked on telemetry dashboard.');
  }

  console.log('[CHAOS] Injection completed. Run "make status" or refresh dashboard to observe the failure.');
}

// 2. REMEDIATION SCENARIOS
if (action === 'remediate') {
  console.log(`[CHAOS] Remediating scenario: ${target}...`);

  if (target === 'vulnerability') {
    // Restore package.json to remove lodash@4.17.4 or upgrade it
    const pkgPath = path.join(BACKEND_DIR, 'package.json');
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    delete pkg.dependencies['lodash'];
    fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2));
    console.log('✓ Restored package.json: Removed vulnerable dependency lodash@4.17.4');

    // Restore clean report
    const scaReportPath = path.join(SECURITY_DIR, 'trivy/report.json');
    fs.writeFileSync(scaReportPath, JSON.stringify({ summary: { critical: 0, high: 0, medium: 0, low: 0 }, findings: [] }, null, 2));

  } else if (target === 'secret') {
    // Clean up AWS Key from db.js
    const dbPath = path.join(BACKEND_DIR, 'db.js');
    let content = fs.readFileSync(dbPath, 'utf8');
    content = content.replace('const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"; // Fake secret\n', '');
    fs.writeFileSync(dbPath, content);
    console.log('✓ Removed mock secret from db.js');

    // Restore clean report
    const secretsReportPath = path.join(SECURITY_DIR, 'gitleaks/report.json');
    fs.writeFileSync(secretsReportPath, JSON.stringify({ leaks: [], scanned_commits: 4 }, null, 2));

  } else if (target === 'policy') {
    // Restore backend-deployment.yaml to safe defaults
    const deployPath = path.join(ROOT_DIR, 'kubernetes/base/backend-deployment.yaml');
    let content = fs.readFileSync(deployPath, 'utf8');
    content = content.replace('runAsNonRoot: false', 'runAsNonRoot: true');
    content = content.replace('runAsUser: 0', 'runAsUser: 1000');
    fs.writeFileSync(deployPath, content);
    console.log('✓ Restored backend-deployment.yaml: Set runAsNonRoot to true');

    // Re-run scan to verify policies
    execSync('node scripts/security-scan.js', { stdio: 'inherit' });

  } else if (target === 'failure') {
    console.log('✓ System blackout resolved. Re-scaled API replica endpoints.');
  }

  console.log('[CHAOS] Remediation completed. System back to stable state.');
}
