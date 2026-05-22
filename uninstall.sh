#!/usr/bin/env bash
# screamingface — reset / uninstall (dev/staging URL)
# usage: curl -fsSL https://raw.githubusercontent.com/iamtrask/dev/main/uninstall.sh | bash
set -euo pipefail

INSTALL_DIR="${SCREAMINGFACE_HOME:-$HOME/.screamingface}"

# Only touch screamingface's own files. By design we never write outside
# $INSTALL_DIR, so a recursive remove of that single directory is the
# whole cleanup.
if [[ -d "$INSTALL_DIR" ]]; then
  # Refuse to delete suspicious paths — defensive, even though SCREAMINGFACE_HOME
  # should be controlled by the user.
  if [[ "$INSTALL_DIR" == "/" || "$INSTALL_DIR" == "$HOME" || -z "$INSTALL_DIR" ]]; then
    echo "refusing to remove $INSTALL_DIR (looks too broad)." >&2
    exit 1
  fi
  echo "removing $INSTALL_DIR"
  rm -rf -- "$INSTALL_DIR"
  echo "✓ removed."
else
  echo "$INSTALL_DIR not present. nothing to clean."
fi

cat <<'EOF'

not touched (by design):
  - macOS Keychain entries (screamingface never writes there)
  - the Slack desktop app or its cookie store
  - any Slack workspaces, channels, or messages

screamingface is reset. install again with:
  curl -fsSL https://raw.githubusercontent.com/iamtrask/dev/main/install.sh | bash
EOF
