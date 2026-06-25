.PHONY: help install install-dev test test-core test-pipeline test-cli test-server \
       lint clean dist dist-clean airgap release bump\:patch bump\:minor bump\:major

.DEFAULT_GOAL := help

# Airgap bundle Python versions (override: make airgap AIRGAP_PYTHON=39,311,312)
AIRGAP_PYTHON ?= 39,311,312

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
test: ## Run full test suite
	pytest packages/core/tests packages/pipeline/tests packages/cli/tests packages/server/tests -v

test-core: ## Run core package tests
	pytest packages/core/tests -v

test-pipeline: ## Run pipeline package tests
	pytest packages/pipeline/tests -v

test-cli: ## Run CLI package tests
	pytest packages/cli/tests -v

test-server: ## Run server package tests
	pytest packages/server/tests -v

##@ Quality
lint: ## Run pylint and mypy
	pylint packages/core/src packages/pipeline/src packages/cli/src packages/server/src
	mypy packages/core/src packages/pipeline/src packages/cli/src packages/server/src

##@ Build
dist: ## Build all package wheels
	python3 -m pip install --quiet build
	python3 -m build --wheel --outdir dist/ packages/core
	python3 -m build --wheel --outdir dist/ packages/pipeline
	python3 -m build --wheel --outdir dist/ packages/cli
	python3 -m build --wheel --outdir dist/ packages/server
	@echo ""
	@echo "Wheels built:"
	@ls -1 dist/*.whl

airgap: ## Build airgap bundles for RHEL 9 x86_64
	./scripts/build-airgap.sh --python $(AIRGAP_PYTHON)

dist-clean: ## Remove dist artifacts
	rm -rf dist/ build/
	find . -type d -name '*.egg-info' -exec rm -rf {} + 2>/dev/null || true

clean: dist-clean ## Remove all build artifacts
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf htmlcov .coverage

##@ Release
bump\:patch: ## Bump patch version (e.g. 2.0.0 -> 2.0.1) across all packages
	@python3 -c "$$BUMP_SCRIPT" patch $(PYPROJECT_FILES)

bump\:minor: ## Bump minor version (e.g. 2.0.1 -> 2.1.0) across all packages
	@python3 -c "$$BUMP_SCRIPT" minor $(PYPROJECT_FILES)

bump\:major: ## Bump major version (e.g. 2.1.0 -> 3.0.0) across all packages
	@python3 -c "$$BUMP_SCRIPT" major $(PYPROJECT_FILES)

release: dist airgap ## Create GitHub release (gh CLI or manual instructions)
	@VERSION=$$(python3 -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])" 2>/dev/null || python3 -c "import tomli as tomllib; print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])"); \
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
		echo "4. Attach these files from dist/:"; \
		echo ""; \
		ls dist/*.whl dist/*.tar.gz dist/SHA256SUMS 2>/dev/null | sort -u | sed 's/^/   /'; \
		echo ""; \
		echo "5. Verify checksums match dist/SHA256SUMS after upload."; \
		echo ""; \
	else \
		echo ""; \
		echo "Release artifacts:"; \
		ls dist/*.whl dist/*.tar.gz dist/SHA256SUMS 2>/dev/null; \
		echo ""; \
		echo "Creating release..."; \
		gh release create "$$TAG" \
			--title "FEMUR $$TAG" \
			--generate-notes \
			dist/*.whl \
			dist/*.tar.gz \
			dist/SHA256SUMS; \
		echo ""; \
		echo "Release created: $$TAG"; \
	fi
