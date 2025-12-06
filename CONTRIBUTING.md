# Contributing to RSC Hunter

Thank you for your interest in contributing to RSC Hunter! This document provides guidelines and instructions for contributing.

## Development Setup

1. **Fork and clone the repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/rschunter.git
   cd rschunter
   ```

2. **Create a virtual environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

4. **Run tests to verify setup**
   ```bash
   python test_rschunter.py
   ```

## Development Workflow

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Write clean, readable code
   - Follow existing code style
   - Add tests for new features
   - Update documentation as needed

3. **Validate your changes**
   ```bash
   chmod +x scripts/validate.sh
   ./scripts/validate.sh
   ```

4. **Commit your changes**
   ```bash
   git add .
   git commit -m "Description of changes"
   ```

5. **Push and create a pull request**
   ```bash
   git push origin feature/your-feature-name
   ```

## Code Style Guidelines

- **Python version**: Target Python 3.8+
- **Line length**: Maximum 120 characters
- **Formatting**: Use `black` for code formatting
- **Import sorting**: Use `isort` for import organization
- **Docstrings**: Use triple-quoted strings for all functions and classes
- **Type hints**: Use where appropriate for clarity

### Auto-format your code
```bash
black rschunter.py test_rschunter.py
isort rschunter.py test_rschunter.py
```

## Testing Guidelines

- All new features must include unit tests
- Tests should be independent and repeatable
- Use mocking for external dependencies
- Maintain or improve test coverage

### Run tests
```bash
python test_rschunter.py
```

### Add new tests
Add test methods to appropriate test classes in `test_rschunter.py`:
- `TestUrlParser` - URL parsing and normalization
- `TestRscScanner` - Detection methods
- `TestMassScanner` - Mass scanning features
- `TestScanStateManager` - State management
- etc.

## Pull Request Process

1. **Update documentation** if you're adding features
2. **Add tests** for new functionality
3. **Run validation** before submitting
4. **Write a clear PR description** explaining:
   - What problem does it solve?
   - How does it solve it?
   - Any breaking changes?
5. **Link related issues** if applicable

## Areas for Contribution

### High Priority
- Additional detection signatures for RSC vulnerabilities
- Performance optimizations for mass scanning
- Enhanced error handling and recovery
- Cross-platform compatibility improvements

### Medium Priority
- More exploit payload variations
- Additional output formats (JSON, CSV, XML)
- Integration with other security tools
- Web UI for results visualization

### Documentation
- Tutorial videos or guides
- More usage examples
- FAQ section
- Translation to other languages

### Testing
- Integration tests
- Performance benchmarks
- Edge case coverage
- Fuzzing tests

## Reporting Bugs

When reporting bugs, please include:

1. **Environment details**
   - OS and version
   - Python version
   - RSC Hunter version

2. **Steps to reproduce**
   - Exact commands used
   - Input files (sanitized)
   - Expected vs actual behavior

3. **Error messages**
   - Full stack traces
   - Relevant log output

4. **Additional context**
   - Screenshots if applicable
   - Network conditions
   - Target characteristics

## Security Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

Instead, please email security concerns directly to the maintainers or use GitHub's private security advisory feature.

## Code of Conduct

### Our Standards

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive criticism
- Accept responsibility for mistakes
- Put community interests first

### Unacceptable Behavior

- Harassment or discriminatory language
- Trolling or insulting comments
- Public or private harassment
- Publishing others' private information
- Unethical or illegal use of the tool

## Release Process

Releases are automated via GitHub Actions:

1. Update version in code and README
2. Run tests and validation
3. Create annotated git tag: `git tag -a v2.0.1 -m "Release v2.0.1"`
4. Push tag: `git push origin v2.0.1`
5. GitHub Actions will automatically:
   - Run CI tests
   - Build release artifacts
   - Create GitHub release
   - Build and push Docker image

## Questions?

- Open a discussion on GitHub
- Check existing issues and PRs
- Review the README and documentation

Thank you for contributing to RSC Hunter!
