#!/usr/bin/env bash
# screamingface — quiet install (dev/staging URL)
# usage: curl -fsSL https://raw.githubusercontent.com/iamtrask/dev/main/install.sh | bash
set -euo pipefail

INSTALL_DIR="${SCREAMINGFACE_HOME:-$HOME/.screamingface}"
REPO_RAW="https://raw.githubusercontent.com/iamtrask/dev/main"

# 1) platform sanity
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "screamingface is macOS-only for v0. detected: $(uname -s)" >&2
  exit 1
fi

# 2) python sanity
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found on PATH. install Python 3.11+ and re-run." >&2
  exit 1
fi

# 3) system tools that send.py shells out to
for tool in security openssl sqlite3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "required tool '$tool' not found on PATH. (it ships with macOS — your env may be unusual.)" >&2
    exit 1
  fi
done

# 4) prepare install dir (payload TBD)
mkdir -p "$INSTALL_DIR"

# 5) report
PY_VERSION="$(python3 -c 'import sys; print(sys.version.split()[0])')"
echo ""
echo "✓ screamingface placeholder install ok."
echo "  install dir: $INSTALL_DIR"
echo "  python3:     $PY_VERSION"
echo "  (payload not yet shipped; this is a staging-URL probe.)"
