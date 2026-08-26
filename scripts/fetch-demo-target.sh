#!/usr/bin/env bash
#
# Fetches OWASP Juice Shop into demo-app/juice-shop, the default source-code
# scan target used by GitLeaks and SonarQube (TARGET_PATH=./demo-app in
# .env.example). Not vendored in this repo to keep it small - this script
# clones it on demand instead. Idempotent: does nothing if already present.
#
#   scripts/fetch-demo-target.sh
#
# Skip this entirely if you're pointing ThreatWeave at your own project via
# TARGET_PATH - it's only needed for the bundled demo.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$HERE/demo-app/juice-shop"
VERSION="${JUICE_SHOP_VERSION:-v20.1.1}"
REPO="https://github.com/juice-shop/juice-shop.git"

if [ -d "$DEST/.git" ]; then
    echo "==> demo-app/juice-shop already present, leaving it as-is"
    exit 0
fi

echo "==> Cloning OWASP Juice Shop ($VERSION) into demo-app/juice-shop"
mkdir -p "$HERE/demo-app"
git clone --depth 1 --branch "$VERSION" "$REPO" "$DEST"
echo "==> Done. TARGET_PATH=./demo-app in .env.example already points here."
