# Contributing to SkillGuard

Thank you for your interest in contributing to SkillGuard!

## Development Setup

1. Clone the repository:
```bash
git clone https://github.com/your-org/skillguard.git
cd skillguard
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install development dependencies:
```bash
pip install -e ".[dev]"
```

4. Install pre-commit hooks:
```bash
pre-commit install
```

## Running Tests

```bash
pytest
pytest --cov=skillguard  # With coverage
```

## Code Style

We use:
- **Black** for code formatting
- **isort** for import sorting
- **Ruff** for linting
- **mypy** for type checking

Run all checks:
```bash
black src tests
isort src tests
ruff check src tests
mypy src
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run tests and linting
5. Commit with clear messages
6. Push and create a Pull Request

## Adding New Detection Rules

To add a new SIFA detection rule:

1. Add the pattern to `src/skillguard/detection/sifa.py`
2. Add corresponding test in `tests/test_sifa.py`
3. Update documentation in `docs/sifa.md`

## Reporting Bugs

Please include:
- Python version
- OS
- Steps to reproduce
- Expected vs actual behavior

## Feature Requests

Open an issue with the "enhancement" label.

## Code of Conduct

Be respectful and constructive in all interactions.
