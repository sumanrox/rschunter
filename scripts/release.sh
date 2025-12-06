#!/bin/bash
# Release script for RSC Hunter
# Usage: ./scripts/release.sh <version>

set -e

VERSION=$1

if [ -z "$VERSION" ]; then
    echo "Usage: ./scripts/release.sh <version>"
    echo "Example: ./scripts/release.sh 2.0.0"
    exit 1
fi

echo "================================================"
echo "  RSC Hunter Release Process"
echo "  Version: $VERSION"
echo "================================================"

# Validate version format
if ! [[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Version must be in format X.Y.Z"
    exit 1
fi

# Check if on main/master branch
BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [[ "$BRANCH" != "main" && "$BRANCH" != "master" ]]; then
    echo "Warning: Not on main/master branch (current: $BRANCH)"
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check for uncommitted changes
if ! git diff-index --quiet HEAD --; then
    echo "Error: Uncommitted changes detected. Commit or stash them first."
    exit 1
fi

# Run tests
echo ""
echo "Step 1/5: Running tests..."
python3 test_rschunter.py
if [ $? -ne 0 ]; then
    echo "Error: Tests failed. Fix issues before releasing."
    exit 1
fi
echo "✓ Tests passed"

# Update version in README
echo ""
echo "Step 2/5: Updating version in README..."
sed -i.bak "s/v[0-9]\+\.[0-9]\+\.[0-9]\+/v$VERSION/g" README.md
rm -f README.md.bak
echo "✓ Version updated in README"

# Create git tag
echo ""
echo "Step 3/5: Creating git tag..."
git add README.md
git commit -m "Release v$VERSION" || true
git tag -a "v$VERSION" -m "Release version $VERSION"
echo "✓ Git tag created: v$VERSION"

# Push to remote
echo ""
echo "Step 4/5: Pushing to remote..."
read -p "Push to remote? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    git push origin $BRANCH
    git push origin "v$VERSION"
    echo "✓ Pushed to remote"
else
    echo "⚠ Skipped push (manual push required)"
fi

# Generate release notes
echo ""
echo "Step 5/5: Generating release notes..."
cat > "release-notes-v$VERSION.md" << EOF
# RSC Hunter v$VERSION

## Changes

$(git log $(git describe --tags --abbrev=0 HEAD^)..HEAD --pretty=format:"- %s (%h)" 2>/dev/null || echo "- Initial release")

## Installation

\`\`\`bash
# Download and extract
wget https://github.com/YOUR_USERNAME/rschunter/releases/download/v$VERSION/rschunter-$VERSION.tar.gz
tar -xzf rschunter-$VERSION.tar.gz
cd rschunter-$VERSION

# Install dependencies
pip3 install -r requirements.txt

# Run
python3 rschunter.py --help
\`\`\`

## Docker

\`\`\`bash
docker pull ghcr.io/YOUR_USERNAME/rschunter:$VERSION
docker run --rm ghcr.io/YOUR_USERNAME/rschunter:$VERSION --help
\`\`\`

## Checksums

See checksums.txt in release assets for SHA256 verification.
EOF

echo "✓ Release notes generated: release-notes-v$VERSION.md"

echo ""
echo "================================================"
echo "  Release v$VERSION prepared successfully!"
echo "================================================"
echo ""
echo "Next steps:"
echo "1. GitHub Actions will automatically create the release"
echo "2. Review the release at: https://github.com/YOUR_USERNAME/rschunter/releases"
echo "3. Edit release notes if needed"
echo ""
