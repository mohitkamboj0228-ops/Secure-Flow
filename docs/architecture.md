# SecureFlow DevSecOps Platform - Architecture

This document describes the software design and integration layers of the **SecureFlow Platform**.

---

## High-Level Workflow

The delivery lifecycle flows from code checkout to runtime observability, ensuring security validations are completed at every step:

```text
[Developer Commit]
       │
       ▼ (Pre-commit / CI gate)
┌─────────────────────────────────────────────────────────┐
│              Security Pipeline Scanner                  │
│  ├─ Semgrep (SAST Source Linting)                      │
│  ├─ Trivy SCA (Third-Party Dependency Audit)           │
│  └─ Gitleaks (Entropy Secrets Scan)                     │
└──────────────────────────┬──────────────────────────────┘
                           │ (Verify Pass)
                           ▼
┌─────────────────────────────────────────────────────────┐
│                 Container Delivery                      │
│  ├─ Docker Multistage Build (Minimal footprints)        │
│  ├─ Trivy Image Scan (Base OS Layer exploits check)     │
│  ├─ Syft SBOM Generation (CycloneDX Inventory)         │
│  └─ Cosign Cryptographic Sign (Signing local digest)    │
└──────────────────────────┬──────────────────────────────┘
                           │ (Sig Verification)
                           ▼
┌─────────────────────────────────────────────────────────┐
│               Kubernetes Runtime (EKS)                  │
│  ├─ Kyverno (Non-root, Resource limit enforcement)      │
│  ├─ NetworkPolicies (L4 ingress pod isolation)         │
│  └─ ServiceAccount RBAC (Read-only list permissions)     │
└──────────────────────────┬──────────────────────────────┘
                           │ (Expose /metrics)
                           ▼
┌─────────────────────────────────────────────────────────┐
│             Observability & Alerting                    │
│  ├─ Prometheus Server (HTTP & system metrics scraping)  │
│  ├─ AlertManager (Latency & CrashLoop alerts routing)   │
│  └─ Grafana Dashboards (Visual analytics panels)        │
└─────────────────────────────────────────────────────────┘
```

---

## Architectural Decision Records (ADRs)

### ADR-001: Platform Orchestrator (Kubernetes)
- **Status**: Approved
- **Context**: The platform needs to host scalable, multi-component microservices securely.
- **Decision**: Deploy services on **Kubernetes (local Docker Desktop / AWS EKS)**.
- **Consequences**: Standardizes resource isolation, supports HorizontalPodAutoscalers, and enables declarative networking via NetworkPolicies.

### ADR-002: Security Scanners (Trivy, Semgrep, Gitleaks)
- **Status**: Approved
- **Context**: Dependency exploits, hardcoded keys, and basic code vulnerabilities account for 90% of cloud security compromises.
- **Decision**: Embed **Semgrep** (SAST), **Trivy** (SCA & Container Scan), and **Gitleaks** (Secrets detection).
- **Consequences**: Fast, open-source validation gates run locally and inside CI pipelines.

### ADR-003: Software Bill of Materials (SBOM via Syft)
- **Status**: Approved
- **Context**: Compliance requires auditing third-party software components.
- **Decision**: Use **Syft** to generate structured CycloneDX packages bills.
- **Consequences**: Clear dependency catalog allows tracking and patching vulnerabilities.

### ADR-004: Container Supply Chain (Cosign Signing)
- **Status**: Approved
- **Context**: Preventing unauthorized images from launching in production.
- **Decision**: Sign image digests using **Cosign** keys.
- **Consequences**: Unsigned images fail policy admission and are rejected by Kyverno.
