.PHONY: test-newtools test-agentic-docker platform-up test-package e2e-agent test-onboarding e2e-fastapi sonar-up sonar-down selftest dashboard build-scanner
platform-up:    ## SonarQube + dashboard on this server (see docs/dashboard.md); HOST=<address> to set the URLs it prints
	scripts/platform-up.sh $(if $(HOST),--host $(HOST),)
sonar-up:        ## start central SonarQube on http://localhost:9000
	cd docker && docker compose --env-file ../versions.env up -d
sonar-down:
	cd docker && docker compose --env-file ../versions.env down
selftest:        ## prove the gate logic (~2 min, needs Docker + internet for the first Trivy DB download)
	scripts/selftest.sh
dashboard:
	scripts/aggregate.py
build-scanner:
	scripts/secscan pull
e2e-fastapi:     ## build+run the vulnerable FastAPI sample and scan it with every layer incl. ZAP (~6 min)
	scripts/e2e-fastapi.sh
test-newtools:  ## real-container test of the newer checks: git history, SBOM, workflows, K8s, fuzzing, exposure, SLA (~3 min)
	scripts/test-newtools.sh

test-agentic-docker: ## sandbox + Vault tests that need Docker (pulls the Vault image the first time, ~400 MB)
	python3 -W ignore -I agentic/tests/test_sandbox_docker.py && python3 -W ignore -I agentic/tests/test_vault_docker.py

test-package: ## build + pip-install into a clean venv; init/shim/disable/uninstall (~3 min, needs network + Docker)
	scripts/test-package.sh

test-onboarding: ## developer-journey test on python, node and java (~6 min)
	scripts/test-onboarding.sh
e2e-agent:      ## vulnerable vs hardened AI agent: static + inventory + Semgrep rules + red-team probes, with assertions (~2 min)
	scripts/e2e-agent.sh
