.PHONY: platform-up test-package e2e-agent test-onboarding e2e-fastapi sonar-up sonar-down selftest dashboard build-scanner
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
	. ./versions.env && docker build -t $$SCANNER_IMAGE --build-arg BANDIT_VERSION=$$BANDIT_VERSION --build-arg PIP_AUDIT_VERSION=$$PIP_AUDIT_VERSION docker/scanner
e2e-fastapi:     ## build+run the vulnerable FastAPI sample and scan it with every layer incl. ZAP (~6 min)
	scripts/e2e-fastapi.sh
test-package: ## build + pip-install into a clean venv; init/shim/disable/uninstall (~3 min, needs network + Docker)
	scripts/test-package.sh

test-onboarding: ## developer-journey test on python, node and java (~6 min)
	scripts/test-onboarding.sh
e2e-agent:      ## vulnerable vs hardened AI agent: static + inventory + Semgrep rules + red-team probes, with assertions (~2 min)
	scripts/e2e-agent.sh
