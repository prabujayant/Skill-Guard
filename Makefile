# SkillGuard Makefile

.PHONY: install dev test lint format clean docs run-demo

# Install production dependencies
install:
	pip install -e .

# Install development dependencies
dev:
	pip install -e ".[dev]"
	pre-commit install

# Run tests
test:
	pytest tests/ -v --cov=skillguard --cov-report=html

# Run tests with coverage report
test-cov:
	pytest tests/ -v --cov=skillguard --cov-report=term-missing --cov-report=html

# Lint code
lint:
	ruff check src/ tests/
	mypy src/

# Format code
format:
	black src/ tests/
	isort src/ tests/

# Clean build artifacts
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	rm -rf htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

# Build documentation
docs:
	mkdocs build

# Serve documentation locally
docs-serve:
	mkdocs serve

# Run demo script
run-demo:
	python scripts/demo.py

# Generate red team samples
generate-redteam:
	python scripts/generate_redteam.py

# Generate paper figures
generate-figures:
	python scripts/visualize.py

# Run full analysis on examples
analyze-examples:
	skillguard analyze examples/benign/calculator
	skillguard analyze examples/malicious/trojan_converter
	skillguard analyze examples/malicious/reverse_shell

# Scrape GitHub for skills (requires GITHUB_TOKEN)
scrape:
	skillguard scrape -n 50 -o data/corpus.json

# Evaluate on labeled dataset
evaluate:
	skillguard evaluate data/labeled/ground_truth.json -o output/evaluation.json
