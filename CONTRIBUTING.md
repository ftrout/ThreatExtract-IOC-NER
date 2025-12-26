# Contributing to ThreatExtract-IOC-NER

Thank you for your interest in contributing to ThreatExtract-IOC-NER! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for all contributors.

## How to Contribute

### Reporting Bugs

Before creating a bug report:
1. Check the existing issues to avoid duplicates
2. Collect relevant information (error messages, environment details)

When creating a bug report, include:
- A clear, descriptive title
- Steps to reproduce the issue
- Expected vs. actual behavior
- Environment details (Python version, OS, package versions)
- Any relevant logs or error messages

### Suggesting Enhancements

Enhancement suggestions are welcome! Please include:
- A clear description of the proposed feature
- Use cases and benefits
- Any potential drawbacks or alternatives considered

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Make your changes** following our coding standards
3. **Add tests** for any new functionality
4. **Update documentation** as needed
5. **Run the test suite** to ensure everything passes
6. **Submit your pull request** with a clear description

## Development Setup

### Prerequisites

- Python 3.9 or higher
- Git
- pip or conda

### Setting Up Your Environment

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/ThreatExtract-IOC-NER.git
cd ThreatExtract-IOC-NER

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src --cov-report=term-missing

# Run specific test file
pytest tests/test_labels.py -v
```

### Code Quality

We use several tools to maintain code quality:

```bash
# Format code with Black
black src/ scripts/ tests/

# Sort imports with isort
isort src/ scripts/ tests/

# Check style with flake8
flake8 src/ scripts/ tests/

# Type checking with mypy
mypy src/
```

All these checks run automatically via pre-commit hooks.

## Coding Standards

### Python Style

- Follow PEP 8 guidelines
- Use Black for formatting (100 character line length)
- Use type hints for function signatures
- Write docstrings for public functions and classes

### Example

```python
def extract_iocs(
    text: str,
    entity_types: Optional[List[str]] = None,
    min_confidence: float = 0.5,
) -> List[ExtractedIOC]:
    """
    Extract IOCs from threat intelligence text.

    Args:
        text: The input text to process
        entity_types: Optional filter for specific entity types
        min_confidence: Minimum confidence threshold (0-1)

    Returns:
        List of extracted IOC objects

    Raises:
        ValueError: If min_confidence is not between 0 and 1
    """
    ...
```

### Commit Messages

- Use clear, descriptive commit messages
- Start with a verb in present tense (e.g., "Add", "Fix", "Update")
- Reference relevant issues when applicable

Examples:
- `Add support for MITRE ATT&CK technique extraction`
- `Fix entity span calculation for multi-word IOCs`
- `Update documentation for Hugging Face deployment`

## Areas for Contribution

### High Priority

- **Training Data**: Help curate high-quality labeled threat intelligence data
- **Entity Coverage**: Extend support for additional IOC types
- **Validation Patterns**: Improve regex patterns for IOC validation
- **Documentation**: Enhance tutorials and examples

### Other Areas

- Performance optimizations
- Additional output formats (OpenIOC, MISP)
- Integration examples with security tools
- Internationalization support

## Adding New Entity Types

To add support for a new IOC type:

1. **Update labels.py**: Add the entity type to `IOC_ENTITY_TYPES`
2. **Update validation patterns**: Add regex patterns to `IOCValidator.PATTERNS` in `pipeline.py`
3. **Update color scheme**: Add a color for the entity in `ENTITY_COLORS`
4. **Add training templates**: Include examples in `generate_sample_data.py`
5. **Add tests**: Write tests for the new entity type
6. **Update documentation**: Document the new entity type in README and MODEL_CARD

## Questions?

Feel free to open an issue for any questions about contributing. We're happy to help!

## License

By contributing to ThreatExtract-IOC-NER, you agree that your contributions will be licensed under the MIT License.
