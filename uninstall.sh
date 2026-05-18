#!/usr/bin/env bash
# iocscan project-only uninstall.
#
# Removes ONLY files and directories created by this project. System-wide
# tools (python3, git, gh, pip, Homebrew, etc.) and other Python projects
# are NOT touched.
#
# Each destructive step asks for confirmation before running.

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER_DATA="$HOME/.iocscan"

confirm() {
  local prompt="$1"
  local reply
  read -r -p "  $prompt [y/N] " reply
  [[ "$reply" =~ ^[Yy]$ ]]
}

echo "==> iocscan project-only uninstall"
echo "    Project dir: $PROJECT_DIR"
echo "    User data:   $USER_DATA"
echo
echo "    This script will NOT touch python3, git, gh, pip, or any other"
echo "    system-wide tool. Other projects on this machine are unaffected."
echo

# -----------------------------------------------------------------------------
# Step 1 — user data (~/.iocscan/): API keys, TI cache, Tranco whitelist
# -----------------------------------------------------------------------------
if [[ -d "$USER_DATA" ]]; then
  echo "[1/4] User data at $USER_DATA"
  echo "      Contains: config.toml (API keys), cache.db (TI lookups),"
  echo "                tranco-1k.txt (whitelist cache)."

  if [[ -f "$USER_DATA/config.toml" ]] && confirm "Back up config.toml to ~/iocscan-config-backup.toml first?"; then
    cp "$USER_DATA/config.toml" "$HOME/iocscan-config-backup.toml"
    chmod 0600 "$HOME/iocscan-config-backup.toml"
    echo "      -> backup saved (mode 0600)."
  fi

  if confirm "Remove $USER_DATA?"; then
    rm -rf "$USER_DATA"
    echo "      removed."
  else
    echo "      skipped."
  fi
else
  echo "[1/4] $USER_DATA does not exist — skipped."
fi
echo

# -----------------------------------------------------------------------------
# Step 2 — project venv (.venv/): httpx, rich, pytest, ...
# -----------------------------------------------------------------------------
VENV="$PROJECT_DIR/.venv"
if [[ -d "$VENV" ]]; then
  echo "[2/4] Project venv at $VENV"
  echo "      Contains httpx, rich, tomli-w (and pytest/coverage if dev extras"
  echo "      were installed). Only this venv is affected — system Python and"
  echo "      other projects' venvs are untouched."
  if confirm "Remove $VENV?"; then
    rm -rf "$VENV"
    echo "      removed."
  else
    echo "      skipped."
  fi
else
  echo "[2/4] $VENV does not exist — skipped."
fi
echo

# -----------------------------------------------------------------------------
# Step 3 — project source tree
# -----------------------------------------------------------------------------
echo "[3/4] Project source tree at $PROJECT_DIR"
echo "      This removes: source code, tests, docs, and the local .git/"
echo "      history. Any uncommitted local changes will be lost."
echo "      Note: the script will delete itself during this step."

if confirm "Remove $PROJECT_DIR?"; then
  parent="$(dirname "$PROJECT_DIR")"
  # cd out before rm so we don't delete our own CWD
  cd "$parent"
  rm -rf "$PROJECT_DIR"
  echo "      removed."
else
  echo "      skipped."
fi
echo

# -----------------------------------------------------------------------------
# Step 4 — GitHub remote (manual, irreversible)
# -----------------------------------------------------------------------------
echo "[4/4] GitHub remote repository — manual, not automated."
echo
echo "      This script does NOT delete the GitHub repo. Deleting a GitHub"
echo "      repo is irreversible and there is rarely a good reason. If you"
echo "      really want to remove it, run manually:"
echo
echo "          gh repo delete erhanersoyy/iocscan --yes"
echo

echo "==> done."
echo
echo "Verify nothing project-specific is left:"
echo "    ls $USER_DATA       # No such file or directory"
echo "    ls $PROJECT_DIR     # No such file or directory"
