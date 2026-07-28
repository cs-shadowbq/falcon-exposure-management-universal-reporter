.PHONY: help install install-dev test test-core test-pipeline test-cli test-server \
       test-coverage test-coverage-serve workflows version \
       lint clean man build dist dist-clean dist-host airgap release bump-patch bump-minor bump-major \
       _ensure-test

.DEFAULT_GOAL := help

# Airgap bundle Python versions (override: make airgap AIRGAP_PYTHON=39,311,312)
AIRGAP_PYTHON ?= 39,311,312

# Current project version (read from root pyproject.toml). Build artifacts are
# written to a version-scoped subdirectory so different versions never mingle
# and SHA256SUMS only ever covers a single release.
VERSION := $(shell python3 -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])" 2>/dev/null || python3 -c "import tomli as tomllib; print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])")
DIST_DIR := dist/$(VERSION)

# Man pages are generated from the argparse parsers plus the hand-authored roff
# includes (DESCRIPTION/ENVIRONMENT/FILES/EXAMPLES/...). The dynamic option
# surface comes from the parsers via argparse-manpage, so it never drifts from
# --help; only the prose in the includes is maintained.
MAN_DIR := build
FEMUR_MAN := $(MAN_DIR)/femur.1
FEMURD_MAN := $(MAN_DIR)/femurd.1
FEMUR_MAN_INCLUDE := dist-templates/femur.1.include
FEMURD_MAN_INCLUDE := dist-templates/femurd.1.include

PYPROJECT_FILES := pyproject.toml \
    packages/core/pyproject.toml \
    packages/pipeline/pyproject.toml \
    packages/cli/pyproject.toml \
    packages/server/pyproject.toml

define BUMP_SCRIPT
import re, sys
kind = sys.argv[1]
files = sys.argv[2:]
with open(files[0]) as f:
    m = re.search(r'version\s*=\s*"(\d+)\.(\d+)\.(\d+)"', f.read())
M, m_, p = int(m.group(1)), int(m.group(2)), int(m.group(3))
old = f"{M}.{m_}.{p}"
if kind == "patch": new = f"{M}.{m_}.{p+1}"
elif kind == "minor": new = f"{M}.{m_+1}.0"
else: new = f"{M+1}.0.0"
print(f"Bumping version: {old} -> {new}")
for path in files:
    with open(path) as f: content = f.read()
    with open(path, "w") as f: f.write(content.replace(f'version = "{old}"', f'version = "{new}"'))
    print(f"  {path}")
print(f'Next: git commit -am "Release v{new}" && git tag v{new} && git push --tags')
endef
export BUMP_SCRIPT

##@ General
help: ## Show this help
	@awk '\
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5); next } \
		/^[a-zA-Z_\\].*: .*## / { target=$$0; sub(/: .*/, "", target); gsub(/\\/, "", target); desc=$$0; sub(/.*## /, "", desc); printf "  \033[36m%-16s\033[0m %s\n", target, desc } \
		BEGIN { printf "\nUsage:\n  make \033[36m<target>\033[0m\n" }' $(MAKEFILE_LIST)

##@ Development
install: ## Install all packages in editable mode
	pip install -e packages/core
	pip install -e packages/pipeline
	pip install -e packages/cli
	pip install -e packages/server

install-dev: install ## Install with test/dev extras
	pip install pytest pytest-cov pytest-mock bandit mypy pylint

##@ Testing
# Ensure the packages + test tooling are importable before running pytest, so a
# fresh clone can `make test` without a separate `make install-dev` first. Quiet
# and idempotent — pip skips anything already satisfied.
_ensure-test:
	@python3 -c "import pytest, pytest_cov, pytest_mock" >/dev/null 2>&1 || \
		pip install --quiet -e packages/core -e packages/pipeline -e packages/cli -e packages/server pytest pytest-cov pytest-mock

test: _ensure-test ## Run full test suite
	pytest packages/core/tests packages/pipeline/tests packages/cli/tests packages/server/tests -v

test-core: _ensure-test ## Run core package tests
	pytest packages/core/tests -v

test-pipeline: _ensure-test ## Run pipeline package tests
	pytest packages/pipeline/tests -v

test-cli: _ensure-test ## Run CLI package tests
	pytest packages/cli/tests -v

test-server: _ensure-test ## Run server package tests
	pytest packages/server/tests -v

test-coverage: _ensure-test ## Run tests with coverage report (HTML into htmlcov/)
	pytest packages/core/tests packages/pipeline/tests packages/cli/tests packages/server/tests \
		--cov=packages/core/src --cov=packages/pipeline/src --cov=packages/cli/src --cov=packages/server/src \
		--cov-report=html --cov-report=term

test-coverage-serve: test-coverage ## Run coverage + serve the HTML report at http://localhost:8089
	@echo "Serving coverage report at http://localhost:8089 ..."
	python3 -m http.server 8089 --directory htmlcov

##@ Quality
lint: ## Run pylint and mypy
	pylint packages/core/src packages/pipeline/src packages/cli/src packages/server/src
	mypy packages/core/src packages/pipeline/src packages/cli/src packages/server/src

workflows: ## Mirror CI locally (bandit + pylint, same invocations as .github/workflows)
	@python3 -m pip install --quiet bandit pylint
	@echo "Running Bandit security scan..."
	bandit -r packages/core/src packages/pipeline/src packages/cli/src packages/server/src -ll -ii -s B104
	@echo "Running Pylint..."
	pylint packages/core/src packages/pipeline/src packages/cli/src packages/server/src --disable=R0801,C0411,C0301,C0413,C0415,W0613 --exit-zero

##@ Build
dist: ## Build all package wheels into dist/<version>/
	python3 -m pip install --quiet build
	python3 -m build --wheel --outdir $(DIST_DIR)/ packages/core
	python3 -m build --wheel --outdir $(DIST_DIR)/ packages/pipeline
	python3 -m build --wheel --outdir $(DIST_DIR)/ packages/cli
	python3 -m build --wheel --outdir $(DIST_DIR)/ packages/server
	@echo ""
	@echo "Verifying wheels install and the binaries report the right version..."
	@python3 -m pip install --quiet --force-reinstall --find-links $(DIST_DIR)/ femur-cli femur-server
	@femur --version
	@femurd --version
	@echo ""
	@echo "Wheels built into $(DIST_DIR)/:"
	@ls -1 $(DIST_DIR)/*.whl

airgap: build ## Build airgap bundles (wheels + deps + lockfile + SBOM + man pages) into dist/<version>/
	./scripts/build-airgap.sh --python $(AIRGAP_PYTHON)

man: ## Generate man pages (build/femur.1, build/femurd.1) from the argparse parsers
	@echo "Generating man pages for v$(VERSION)..."
	@mkdir -p $(MAN_DIR)
	@python3 -m pip install --quiet argparse-manpage
	@python3 -m pip install --quiet -e packages/core -e packages/pipeline -e packages/cli -e packages/server >/dev/null 2>&1
	@argparse-manpage \
		--module femur_cli.parser --function build_parser \
		--prog femur --project-name "femur-cli" \
		--version "$(VERSION)" \
		--description "download CrowdStrike Falcon inventory, vulnerabilities, and assessments" \
		--author "CrowdStrike Community" \
		--url "https://github.com/cs-shadowbq/falcon-exposure-management-universal-reporter" \
		--manual-title "FEMUR Manual" \
		--include $(FEMUR_MAN_INCLUDE) \
		--output $(FEMUR_MAN)
	@argparse-manpage \
		--module femur_server.server.__main__ --function build_parser \
		--prog femurd --project-name "femur-server" \
		--version "$(VERSION)" \
		--description "serve pre-fetched Falcon inventory data over HTTP" \
		--author "CrowdStrike Community" \
		--url "https://github.com/cs-shadowbq/falcon-exposure-management-universal-reporter" \
		--manual-title "FEMUR Manual" \
		--include $(FEMURD_MAN_INCLUDE) \
		--output $(FEMURD_MAN)
	@echo "Wrote $(FEMUR_MAN) and $(FEMURD_MAN)"

build: dist man ## Build wheels + man pages (alias: dist + man)

dist-clean: ## Remove dist artifacts — all versions, or only the given version: make dist-clean 2.1.0
	@if [ -n "$(DIST_CLEAN_VERSIONS)" ]; then \
		for v in $(DIST_CLEAN_VERSIONS); do \
			if [ -d "dist/$$v" ]; then \
				echo "Removing dist/$$v/"; \
				rm -rf "dist/$$v"; \
			else \
				echo "No such version dir: dist/$$v (skipping)"; \
			fi; \
		done; \
	else \
		echo "Removing ALL dist artifacts"; \
		rm -rf dist/ build/; \
		find . -type d -name '*.egg-info' -exec rm -rf {} + 2>/dev/null || true; \
	fi

# Support "make dist-clean <version>" — the version is a second goal to Make.
# Capture it, and turn it into a no-op target so Make does not error out.
ifneq ($(filter dist-clean,$(MAKECMDGOALS)),)
DIST_CLEAN_VERSIONS := $(filter-out dist-clean,$(MAKECMDGOALS))
$(eval $(DIST_CLEAN_VERSIONS):;@:)
endif

clean: dist-clean ## Remove all build artifacts
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf htmlcov .coverage

##@ Release
version: ## Show the current version from pyproject.toml
	@echo "$(VERSION)"

bump-patch: ## Bump patch version (e.g. 2.0.0 -> 2.0.1) across all packages
	@python3 -c "$$BUMP_SCRIPT" patch $(PYPROJECT_FILES)

bump-minor: ## Bump minor version (e.g. 2.0.1 -> 2.1.0) across all packages
	@python3 -c "$$BUMP_SCRIPT" minor $(PYPROJECT_FILES)

bump-major: ## Bump major version (e.g. 2.1.0 -> 3.0.0) across all packages
	@python3 -c "$$BUMP_SCRIPT" major $(PYPROJECT_FILES)

release: airgap ## Runs airgap (builds wheels + bundles), then creates a GitHub release (gh CLI or manual instructions)
	@VERSION="$(VERSION)"; \
	DIST_DIR="$(DIST_DIR)"; \
	TAG="v$$VERSION"; \
	echo ""; \
	echo "=== Creating GitHub Release $$TAG ==="; \
	if ! command -v gh &>/dev/null || ! gh auth status &>/dev/null; then \
		echo ""; \
		echo "gh CLI is not available or not authenticated."; \
		echo "To publish this release manually:"; \
		echo ""; \
		echo "1. Tag the release:"; \
		echo ""; \
		echo "   git tag $$TAG"; \
		echo "   git push origin $$TAG"; \
		echo ""; \
		echo "2. Go to: https://github.com/cs-shadowbq/falcon-exposure-management-universal-reporter/releases/new"; \
		echo ""; \
		echo "3. Select tag: $$TAG"; \
		echo "   Title: FEMUR $$TAG"; \
		echo "   Description: Click 'Generate release notes' for changelog"; \
		echo ""; \
		echo "4. Attach these files from $$DIST_DIR/:"; \
		echo ""; \
		ls $$DIST_DIR/*.whl $$DIST_DIR/*.tar.gz $$DIST_DIR/SHA256SUMS $$DIST_DIR/SHA256SUMS.asc 2>/dev/null | sort -u | sed 's/^/   /'; \
		echo ""; \
		echo "5. Verify checksums match $$DIST_DIR/SHA256SUMS after upload."; \
		echo ""; \
	else \
		echo ""; \
		echo "Release artifacts:"; \
		ls $$DIST_DIR/*.whl $$DIST_DIR/*.tar.gz $$DIST_DIR/SHA256SUMS $$DIST_DIR/SHA256SUMS.asc 2>/dev/null; \
		echo ""; \
		echo "Creating release..."; \
		gh release create "$$TAG" \
			--title "FEMUR $$TAG" \
			--generate-notes \
			$$DIST_DIR/*.whl \
			$$DIST_DIR/*.tar.gz \
			$$DIST_DIR/SHA256SUMS \
			$$(ls $$DIST_DIR/SHA256SUMS.asc 2>/dev/null); \
		echo ""; \
		echo "Release created: $$TAG"; \
	fi
