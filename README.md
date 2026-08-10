# FastAPI Doctor

Professional audit orchestrator for Python/FastAPI projects with advanced static analysis capabilities.

## Overview

FastAPI Doctor is a comprehensive audit tool designed specifically for Python/FastAPI applications. It combines advanced static analysis with security scanning, performance optimization detection, and architectural review capabilities.

## Key Features

### Advanced Static Analysis
- Data flow tracking for sensitive information
- Advanced SQL injection detection
- AST-based Python code analysis
- Performance bottleneck identification

### FastAPI Specific Analysis
- Dependency graph construction and analysis
- Route security validation
- OpenAPI/Swagger schema validation
- Authentication/authorization pattern detection

### Security Scanning
- Secret detection and leakage prevention
- Command injection vulnerability detection
- Path traversal vulnerability scanning
- Dependency vulnerability assessment

### Tool Orchestration
- Integration with Ruff for code quality
- Integration with Mypy for type checking
- Integration with Bandit for security scanning
- Integration with pip-audit for dependency scanning
- Integration with Semgrep for advanced pattern matching

### Reporting
- Multiple output formats (HTML, JSON, SARIF, Text)
- GitHub Code Scanning integration via SARIF
- Detailed metrics and scoring
- Actionable recommendations

## Installation

### From PyPI

```bash
# Basic installation
pip install fastapi-doctor

# Full installation with all features
pip install "fastapi-doctor[full]"
```

### From Source

```bash
git clone https://github.com/guerschom1103/fastapi_doctor.git
cd fastapi_doctor
pip install -e .
```

## Quick Start

### Basic Audit

```bash
# Audit a project
fastapi-doctor --path /path/to/your/project

# Audit with HTML report
fastapi-doctor --path /path/to/your/project --format html --output audit.html

# Audit with SARIF for GitHub Code Scanning
fastapi-doctor --path /path/to/your/project --format sarif --output audit.sarif
```

### Advanced Analysis

```bash
# Deep analysis with data flow tracking
fastapi-doctor --path /path/to/your/project --deep

# Analyze FastAPI dependency graph
fastapi-doctor --path /path/to/your/project --analyze-deps

# Analyze OpenAPI documentation
fastapi-doctor --path /path/to/your/project --analyze-openapi

# Performance analysis
fastapi-doctor --path /path/to/your/project --analyze-performance
```

When run in an interactive terminal, FastAPI Doctor displays an animated phase-by-phase
progress indicator. Machine-readable output stays clean because progress is written to
stderr and is disabled automatically when output is redirected. Use `--progress always`
to force it or `--progress never` to disable it.

Advanced heuristic checks ignore tests by default to avoid treating fixtures and mocks as
production problems. Pass `--include-tests` when those files should also be reviewed. Each
finding includes a confidence level, repeated instances of one rule have diminishing impact
on the score, and the HTML report provides French search and severity/confidence filters.

## Configuration

Create a `.fastapi-doctor.toml` file in your project root:

```toml
[analysis]
deep = true
analyze_deps = true
analyze_openapi = true
analyze_performance = true

[thresholds]
fail_on = "MEDIUM"
max_file_size_mb = 50

[exclusions]
paths = ["tests/", "migrations/", "__pycache__/"]
patterns = ["*_test.py", "test_*.py"]
```

## CI/CD Integration

### GitHub Actions

```yaml
name: FastAPI Doctor Audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - name: Install FastAPI Doctor
        run: pip install fastapi-doctor[full]
      - name: Run audit
        run: fastapi-doctor --path . --deep --fail-on HIGH --format sarif --output audit.sarif
      - name: Upload SARIF report
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: audit.sarif
```

## Architecture

FastAPI Doctor follows a modular architecture:

```
fastapi-doctor/
├── modules/
│   ├── analyzers/          # Specialized analyzers
│   │   ├── dataflow.py     # Data flow analysis
│   │   ├── sql_injection.py # SQL injection detection
│   │   ├── fastapi_deps.py # FastAPI dependency analysis
│   │   ├── openapi.py      # OpenAPI validation
│   │   ├── performance.py  # Performance analysis
│   │   ├── async_analysis.py # Async/await analysis
│   │   ├── pydantic_analysis.py # Pydantic model analysis
│   │   └── architecture.py # Architectural analysis
│   ├── reporters/          # Report generators
│   └── utils/             # Utility functions
├── tests/                  # Unit tests
└── fastapi_doctor.py       # Main entry point
```

## Development

### Setting Up Development Environment

```bash
# Clone repository
git clone https://github.com/guerschom1103/fastapi_doctor.git
cd fastapi_doctor

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[full]"
pip install pytest ruff mypy

# Run tests
pytest tests/ -v
```

### Adding New Analyzers

1. Create analyzer in `modules/analyzers/`
2. Import and integrate in `fastapi_doctor.py`
3. Add tests in `tests/`
4. Update documentation

## Documentation

For detailed documentation, see [DOCUMENTATION.md](DOCUMENTATION.md).

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Author

guerschom1103

## Disclaimer

FastAPI Doctor is a static analysis tool. It does not replace human code review, penetration testing, or comprehensive security analysis. Results should be interpreted by security professionals.
