# Changelog

All notable changes to the SecureFlow DevSecOps Platform will be documented in this file.

## [1.0.0] - 2026-08-25

### Added
- **Interactive Demo Control Panel**: Visual workflow checks linking simulated chaos to live scanner gate validations.
- **Dynamic Observability Tracking**: Telemetry endpoints mapping HTTP requests rate and latency averages on charts.
- **GitHub Actions workflows**: Pages configuration to host the dashboard statically and security checking pipeline.
- **Kubernetes Client Watcher**: Direct `kubectl` query capabilities for listing active container metrics dynamically.

### Fixed
- **Stuck Loading Screen**: Implemented offline mock state fallbacks inside frontend scripts when backend endpoint checks fail.
- **Health Probes Authorization**: PostgreSQL pg_isready probes updated to dynamically check auth parameters via environment parameters.
- **Docker Compose Status Sync**: Replaced curl utility checking calls with node native fetches to match Alpine configurations.

### Hardened
- **Security Headers & CORS**: Added CSP policies, Frame protections, and strictly bound API access parameters.
- **Minimal base layers**: Pinned Docker base versions to node/nginx alpine configurations, executing non-root user permissions.
