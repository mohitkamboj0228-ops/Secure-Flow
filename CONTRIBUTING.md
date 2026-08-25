# Contributing to SecureFlow

Thank you for your interest in contributing to the **SecureFlow DevSecOps Reference Platform**!

---

## Contribution Opportunities

We welcome contributions across all areas of the ecosystem:
1. **Security Policies**: Add new Kyverno cluster rules or Open Policy Agent (conftest) rules under `kubernetes/policies/`.
2. **Scanner Tools**: Add integrations for new scanning suites (e.g., SonarQube, Snyk, Grype) inside `scripts/security-scan.js`.
3. **Dashboards**: Improve the telemetry visualizations or add new metric graphs inside the web control panel.
4. **Chaos Scenarios**: Implement new failure modes or automated remediation tasks inside `scripts/chaos-scenario.js`.

---

## Code Contribution Workflow

1. Fork this repository and create your feature branch:
   ```bash
   git checkout -b feature/add-new-security-policy
   ```
2. Make your changes and verify policies locally:
   ```bash
   make security
   ```
3. Run tests to ensure API stability:
   ```bash
   make test
   ```
4. Commit your changes with descriptive messages:
   ```bash
   git commit -m "feat(kyverno): enforce read-only filesystem limits on pods"
   ```
5. Push to your fork and submit a Pull Request.
