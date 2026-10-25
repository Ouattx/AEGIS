# AEGIS OMEGA SHIELD - developer and release tasks.  `make help` lists them.

SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

PYTHON ?= python3
VERSION ?= $(shell $(PYTHON) -c "import re,pathlib;print(re.search(r'^version = \"([^\"]+)\"', pathlib.Path('pyproject.toml').read_text(), re.M).group(1))")
IMAGE ?= aegis-omega:$(VERSION)
REVISION ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
COMPOSE := docker compose -f deploy/docker-compose.yml
DEMO_COMPOSE := docker compose -f deploy/docker-compose.demo.yml
DIST := dist

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_.-]+:.*## / {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ------------------------------------------------------------------ development

.PHONY: install
install: ## Install the package with dev, postgres and llm extras (editable)
	$(PYTHON) -m pip install -e ".[dev,postgres,llm]"

.PHONY: web
web: ## Build the analyst console into web/dist
	cd web && npm ci && npm run build

.PHONY: lint
lint: ## Ruff lint (same gate as CI)
	ruff check .

.PHONY: test
test: ## Full Python test suite
	$(PYTHON) -m pytest -q

.PHONY: test-safety
test-safety: ## Spec section 15 safety tests only
	$(PYTHON) -m pytest -q -m safety

.PHONY: test-web
test-web: ## Console unit tests
	cd web && npm ci && npm test

.PHONY: check
check: lint test test-web ## Everything CI checks except the container

.PHONY: demo
demo: ## Local demo without Docker (synthetic data, dev auth, http://localhost:8000)
	aegis demo --port 8000

# ------------------------------------------------------------------ supply chain

.PHONY: audit
audit: ## Dependency vulnerability audit (pip-audit + npm audit of shipped packages)
	$(PYTHON) -m pip_audit --skip-editable
	cd web && npm audit --omit=dev --audit-level=high

.PHONY: sbom
sbom: ## CycloneDX SBOMs for the Python environment and the console
	mkdir -p $(DIST)
	cyclonedx-py environment --output-format JSON --output-file $(DIST)/sbom-python.cdx.json
	cd web && npm sbom --omit=dev --sbom-format cyclonedx > ../$(DIST)/sbom-web.cdx.json
	@echo "wrote $(DIST)/sbom-python.cdx.json $(DIST)/sbom-web.cdx.json"

.PHONY: sbom-image
sbom-image: ## CycloneDX SBOM of the container image (requires syft)
	mkdir -p $(DIST)
	syft $(IMAGE) -o cyclonedx-json=$(DIST)/sbom-image.cdx.json

# ------------------------------------------------------------------ container

.PHONY: image
image: ## Build the production image
	docker build --build-arg VERSION=$(VERSION) --build-arg REVISION=$(REVISION) -t $(IMAGE) .

.PHONY: smoke
smoke: image ## End-to-end smoke test of the compose stack (PostgreSQL, API, Prometheus)
	AEGIS_IMAGE=$(IMAGE) NO_BUILD=1 deploy/smoke-test.sh

.PHONY: demo-docker
demo-docker: ## Containerised demo on http://localhost:8080
	$(DEMO_COMPOSE) up --build

.PHONY: up
up: deploy/.env ## Start the production stack (postgres + api)
	$(COMPOSE) up -d --build

.PHONY: up-monitoring
up-monitoring: deploy/.env ## Start the stack with Prometheus and Grafana
	$(COMPOSE) --profile monitoring up -d --build

.PHONY: down
down: ## Stop the stack (data volumes are kept)
	$(COMPOSE) --profile monitoring --profile bus down

.PHONY: logs
logs: ## Follow API logs
	$(COMPOSE) logs -f api

.PHONY: backup
backup: deploy/.env ## Consistent backup of PostgreSQL and the AEGIS data volume into ./backups
	deploy/backup.sh

deploy/.env:
	@echo "deploy/.env is missing: cp deploy/.env.example deploy/.env and fill in the REQUIRED values" >&2
	@exit 1

.PHONY: clean
clean: ## Remove build outputs
	rm -rf $(DIST) build *.egg-info .pytest_cache .ruff_cache
