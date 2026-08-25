# SecureFlow Platform - Threat Model

This document outlines the threat modeling assessment for the **SecureFlow DevSecOps Ecosystem Platform**. Threat modeling ensures potential vulnerabilities are mapped to mitigation protocols early in the design cycle.

---

## Threat Matrix

| Threat | Impact | Likelihood | Detection | Prevention | Mitigation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Malicious Third-Party Dependency** | **HIGH**: Can expose runtime nodes to remote execution (RCE) or denial of service (DoS). | **HIGH** | Trivy SCA scan executed in CI pipeline. | Freeze version tags and require lock file checksum verification. | Upgrade npm version immediately and execute auto-remediation. |
| **Compromised Base Container Layer** | **HIGH**: Privilege escalation within local alpine pods leading to host node compromise. | **MEDIUM** | Trivy Container Scan executed on built images. | Restrict base images to official minimal Alpine or Distroless. | Rebuild image from verified hardened alpine patches. |
| **Hardcoded API Secrets Leakage** | **CRITICAL**: Threat actors scrape keys to compromise cloud databases. | **HIGH** | Gitleaks scanner running on local and remote commits. | Implement pre-commit hooks and prevent plain-text configuration. | Revoke keys, rotate credentials, and scrub Git history. |
| **Kubernetes Container Escape** | **CRITICAL**: Malicious processes escape to host Linux kernels. | **LOW** | Falco runtime checks and alert alerts. | Enforce Kyverno policies: `disallow-root-containers`. | Terminate compromised pods and isolate the EKS node. |
| **Lateral Network Spreading** | **MEDIUM**: Compromised web pod crawls database and backend ports. | **MEDIUM** | VPC Security Groups and Flow Logs. | Apply Kubernetes `NetworkPolicies` restricting frontend-to-DB ingress. | Revoke ingress access rules and apply restrictive IP tables. |
| **Compromised CI Runner Node** | **CRITICAL**: Malicious builds inject backdoors in production outputs. | **LOW** | Audited runners logging pipeline hashes. | Limit runner permissions via IAM Roles & Security Zones. | Terminate runner instance, revoke credentials, rebuild cluster. |

---

## Core Security Controls Deployed

1. **Static Auditing (SAST)**: Semgrep scans source code syntax matches before build triggers.
2. **Secrets Prevention**: Gitleaks enforces entropy checks checking for plain-text keys.
3. **Supply Chain Integrity**: Syft generates standard CycloneDX SBOMs, and Cosign keys verify image signatures during admission control.
4. **Least Privilege Runtime**: Containers are configured to drop ALL Linux capabilities, block privilege escalation, and execution with UID 1000 (Non-root).
5. **Network Boundaries**: Ingress is isolated so that database pods deny any incoming packets except from the Backend API service account.
