.PHONY: install install-dev test test-core test-pipeline test-cli test-server lint clean

# Install all packages in editable (development) mode
install:
	pip install -e packages/core
	pip install -e packages/pipeline
	pip install -e packages/cli
	pip install -e packages/server

# Install with test/dev extras
install-dev: install
	pip install pytest pytest-cov pytest-mock bandit mypy pylint

# Run full test suite
test:
	pytest packages/core/tests packages/pipeline/tests packages/cli/tests packages/server/tests -v

# Run tests for individual packages
test-core:
	pytest packages/core/tests -v

test-pipeline:
	pytest packages/pipeline/tests -v

test-cli:
	pytest packages/cli/tests -v

test-server:
	pytest packages/server/tests -v

# Lint
lint:
	pylint packages/core/src packages/pipeline/src packages/cli/src packages/server/src
	mypy packages/core/src packages/pipeline/src packages/cli/src packages/server/src

# Remove build artifacts
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name '*.egg-info' -exec rm -rf {} + 2>/dev/null || true
	rm -rf htmlcov .coverage dist build
