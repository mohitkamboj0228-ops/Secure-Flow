.PHONY: setup security build deploy test status destroy tf-plan

setup:
	@echo "=== [SETUP] Verifying Prerequisites and Dependencies ==="
	@node -v || (echo "Error: Node.js is required but not installed." && exit 1)
	@docker -v || (echo "Error: Docker is required but not installed." && exit 1)
	@kubectl version --client || (echo "Error: kubectl is required but not installed." && exit 1)
	@echo "✓ Prerequisites verified successfully."
	@echo "Installing backend dependencies..."
	@cd app/backend && npm install
	@echo "✓ Setup completed."

security:
	@echo "=== [SECURITY] Executing DevSecOps Security Pipeline ==="
	@node scripts/security-scan.js

build:
	@echo "=== [BUILD] Building Application Container Images ==="
	docker build -t secureflow-backend:latest -f infrastructure/docker/Dockerfile.backend .
	docker build -t secureflow-frontend:latest -f infrastructure/docker/Dockerfile.frontend .
	@echo "✓ Docker images built successfully."

deploy:
	@echo "=== [DEPLOY] Launching Kubernetes Workloads ==="
	kubectl apply -k kubernetes/overlays/dev
	@echo "Deployment manifests applied. Check 'make status' for readiness."

test:
	@echo "=== [TEST] Running Automated API Integration Tests ==="
	@node app/backend/test.js

status:
	@echo "=== [STATUS] Checking DevSecOps Ecosystem State ==="
	@echo "\n--- Kubernetes Workloads ---"
	-kubectl get pods,svc,hpa,pdb -n secureflow
	@echo "\n--- Local Security Reports ---"
	@node -e "const fs = require('fs'); const reports = ['security/semgrep/report.json', 'security/trivy/report.json', 'security/gitleaks/report.json', 'security/sbom/sbom.json', 'security/policies/policy-report.json']; reports.forEach(r => console.log(r + ': ' + (fs.existsSync(r) ? '✓ Found' : '✗ Missing')));"

destroy:
	@echo "=== [DESTROY] Cleaning Up Resources ==="
	-kubectl delete -k kubernetes/overlays/dev
	@echo "✓ Kubernetes resources deleted."

tf-plan:
	@echo "=== [TERRAFORM] Planning AWS Production Architecture ==="
	@cd infrastructure/terraform && terraform init && terraform plan
