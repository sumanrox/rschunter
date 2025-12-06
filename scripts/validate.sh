#!/bin/bash
# Local development validation script
# Run before committing or creating PRs

set -e

echo "================================================"
echo "  RSC Hunter - Development Validation"
echo "================================================"

# Check Python version
echo ""
echo "Checking Python version..."
python3 --version

# Install dev dependencies
echo ""
echo "Installing development dependencies..."
pip3 install -q -r requirements-dev.txt

# Run tests
echo ""
echo "Running unit tests..."
python3 test_rschunter.py

# Code formatting check
echo ""
echo "Checking code formatting..."
black --check rschunter.py test_rschunter.py 2>/dev/null || {
    echo "⚠ Code formatting issues detected. Run: black rschunter.py test_rschunter.py"
}

# Import sorting check
echo ""
echo "Checking import sorting..."
isort --check-only rschunter.py test_rschunter.py 2>/dev/null || {
    echo "⚠ Import sorting issues detected. Run: isort rschunter.py test_rschunter.py"
}

# Linting
echo ""
echo "Running flake8..."
flake8 rschunter.py test_rschunter.py --max-line-length=120 --ignore=E501,W503,E203 || true

# Security scan
echo ""
echo "Running security scan..."
bandit -r rschunter.py -f screen || true

# Dependency check
echo ""
echo "Checking for vulnerable dependencies..."
safety check || true

echo ""
echo "================================================"
echo "  Validation Complete!"
echo "================================================"
