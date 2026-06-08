#!/usr/bin/env bash
#
# Point git at the versioned .githooks directory so the pre-push verification
# gate (and the Git-LFS delegating hooks) are active. Run once per clone.
#
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
git config core.hooksPath .githooks
chmod +x .githooks/* 2>/dev/null || true
echo "✓ core.hooksPath -> .githooks"
echo "  pre-push now runs scripts/verify.sh (then git-lfs)."
