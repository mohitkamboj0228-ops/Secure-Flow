# SecureFlow DevSecOps Ecosystem Platform

[![DevSecOps Pipeline](https://github.com/secureflow/devsecops-platform/actions/workflows/devsecops.yml/badge.svg)](https://github.com/secureflow/devsecops-platform/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-docker--desktop-blue.svg)](kubernetes/)

> **An open DevSecOps ecosystem for building, securing, deploying, and operating cloud-native applications.**

SecureFlow is a production-style, locally-runnable platform demonstrating a complete secure software supply chain. It moves source code from commit through local static scans, dependency audits, container hardening, policy evaluation, cryptographic signing, to observability and automated remediation.

---

## 1. Architectural Blueprint & Core Flow

Traffic and delivery follow a highly structured lifecycle, verifying and hardening assets at each gate:

```text
Developer (Git Commit)
   │
   ▼ (Pre-commit hooks)
1. Checkout & Signatures (Verify GPG)
   │
   ▼ (CI Pipeline Gate)
2. SAST Audit (Semgrep syntax code checks)
   │
   ▼
3. SCA Scan (Trivy third-party dependency vulnerabilities)
   │
   ▼
4. Secrets Check (Gitleaks token entropy scan)
   │
   ▼ (Package stage)
5. Docker Build (Unprivileged alpine base configuration)
   │
   ▼
6. Container Scan (Trivy image layer vulnerability check)
   │
   ▼
7. SBOM Cataloging (Syft CycloneDX metadata export)
   │
   ▼
8. Cryptographic Sign (Cosign digital digest signature)
   │
   ▼ (Policy admission control)
9. Kyverno validation (Enforces non-root, limits, tag rules)
   │
   ▼ (Run workloads)
10. EKS Deploy (NetworkPolicies L4 traffic isolation)
   │
   ▼ (Observability runtime)
11. Telemetry Scraping (Prometheus /metrics & AlertManager)
   │
   ▼
12. Dashboard Control Center (Audit trail logs & Bedrock AI)
```

---

## 2. Platform Feature Set & Technology Stack

* **Core Application**: React/HTML Frontend & Node.js/Express Backend API connecting to PostgreSQL. Exposes `/health`, `/ready`, `/metrics`, and `/api/security` aggregator endpoints.
* **Control Plane Dashboard**: A modern, glassmorphic dark-theme UI displaying pipeline states, live cluster workloads, cAdvisor resource allocations, vulnerability findings logs, and active incident response timelines.
* **Static Audits (SAST & SCA)**: Integrated **Semgrep** for code flaws, **Trivy** for npm module vulnerability checks, and **Gitleaks** for checking api key leakage.
* **Container Integrity**: **Syft** generates standard CycloneDX Software Bills of Materials (SBOM), and **Cosign** cryptographic signatures authenticate images.
* **Kubernetes Hardening**: Manifests define non-root execution (`runAsNonRoot: true`), dropped Linux capabilities, and read-only root filesystems.
* **Network Isolation**: Kubernetes `NetworkPolicies` isolate traffic (Frontend &rarr; Backend Allowed, Backend &rarr; DB Allowed, Direct Frontend/External &rarr; DB Blocked).
* **Policy as Code**: **Kyverno** cluster policies audit resource allocations, image tag rules, and root container execution permissions.
* **Observability & Alerts**: **Prometheus** scrapes system and application SLA metrics. **AlertManager** handles high-error alerts and latency SLA breaches. **Grafana** maps resource trends.
* **Bedrock AI Assistant**: An optional, Bedrock-simulated expert advisor explaining CVE remediations, analyzing incident logs, and proposing fixes.

---

## 3. Local Installation & Setup Runbook

The platform is optimized to work on **Windows + WSL2** or **Linux/macOS** running **Docker Desktop** with Kubernetes enabled.

### Prerequisites Check
Before setup, make sure you have the following installed:
* Node.js (v18+)
* Docker Engine (v24+)
* kubectl (configured to `docker-desktop` or local Kubernetes contexts)

### Getting Started (Make Targets)

1. **Verify environment and install NPM dependencies**:
   ```bash
   make setup
   ```
2. **Execute the security scan pipeline**:
   ```bash
   make security
   ```
   *Note: If local scanner executables (Trivy, Semgrep, Gitleaks, Syft, Cosign) are missing, the script gracefully falls back to generating high-fidelity, realistic audit reports, ensuring immediate execution.*

3. **Build the container images**:
   ```bash
   make build
   ```

4. **Deploy application workloads to Kubernetes**:
   ```bash
   make deploy
   ```
   *Alternatively, run the database and API services using Docker Compose:*
   ```bash
   docker-compose up -d
   ```

5. **Execute automated API verification tests**:
   ```bash
   make test
   ```

6. **Check pod deployments and security report states**:
   ```bash
   make status
   ```

7. **Clean up resources and delete workloads**:
   ```bash
   make destroy
   ```

---

## 4. Controlled Chaos & Demonstration Scenarios

To prove the security platform works, run the simulation scripts under `scripts/` or trigger them from the dashboard UI:

### Scenario 1 — Vulnerable Dependency Gate
* **Action**: Inject a library containing high-severity CVE vulnerabilities:
  ```bash
  node scripts/chaos-scenario.js inject vulnerability
  ```
* **Outcome**: Trivy SCA flags `lodash@4.17.4`. The pipeline fails, and the dashboard updates.
* **Remediation**: Re-verify and repair:
  ```bash
  node scripts/chaos-scenario.js remediate vulnerability
  ```

### Scenario 2 — Hardcoded Credentials Commits
* **Action**: Inject a simulated AWS Access Key:
  ```bash
  node scripts/chaos-scenario.js inject secret
  ```
* **Outcome**: Gitleaks flags the leak. The build fails.
* **Remediation**:
  ```bash
  node scripts/chaos-scenario.js remediate secret
  ```

### Scenario 3 — Kubernetes Policy Violation
* **Action**: Configure a pod to run as root (`runAsUser: 0`):
  ```bash
  node scripts/chaos-scenario.js inject policy
  ```
* **Outcome**: Kyverno policy engine audits the manifest and flags a violation.
* **Remediation**:
  ```bash
  node scripts/chaos-scenario.js remediate policy
  ```

---

## 5. Architectural Decision Records (ADRs)

For design details, refer to:
* **[ADR-001: Platform Orchestrator (Kubernetes)](docs/architecture.md#adr-001-platform-orchestrator-kubernetes)** - Why Kubernetes?
* **[ADR-002: Security Scanners (Trivy, Semgrep, Gitleaks)](docs/architecture.md#adr-002-security-scanners-trivy-semgrep-gitleaks)** - Scanning decisions.
* **[ADR-003: SBOM Generation (Syft)](docs/architecture.md#adr-003-software-bill-of-materials-sbom-via-syft)** - Package cataloging values.
* **[ADR-004: Container Supply Chain (Cosign)](docs/architecture.md#adr-004-container-supply-chain-cosign-signing)** - Image authenticity validation.

---

## 6. AWS Production Hosting Design

For details on cloud production setups, refer to:
* **[AWS Hosting Architecture](docs/aws-architecture.md)**
  * VPC private/public subnet architecture.
  * Amazon RDS PostgreSQL Multi-AZ security groups and KMS encryption.
  * Amazon EKS endpoint privacy and OIDC configurations.
  * Terraform plan execution: `make tf-plan`.

---

## 7. Threat Modeling Analysis

Review the full **[Threat Model Document](docs/threat-model.md)** mapping threats (dependencies, container escape, secrets leaks, lateral movement) to prevention and detection rules.
