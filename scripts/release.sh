#!/usr/bin/env bash
# RTOSploit release script
# Usage: ./scripts/release.sh 0.2.0

set -euo pipefail

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>" >&2
    exit 1
fi

echo "Bumping version to $VERSION..."

# Update pyproject.toml
sed -i "s/^version = .*/version = \"$VERSION\"/" pyproject.toml

# Update __init__.py
sed -i "s/__version__ = .*/__version__ = \"$VERSION\"/" rtosploit/__init__.py

# Tag and commit
git add pyproject.toml rtosploit/__init__.py
git commit -m "chore: bump version to $VERSION"
git tag "v$VERSION"

echo "Done. Push with: git push origin main --tags"
