#!/bin/sh
# Demo for README + CI: grant a short lease, use it, let it expire, audit.
# All random/timestamp output is normalized so the result is deterministic.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export LEASEGUARD_HOME="$(mktemp -d)"
trap 'rm -rf "$LEASEGUARD_HOME"' EXIT
cd "$LEASEGUARD_HOME"

NORM="sed -E -e 's|(--lease )[A-Za-z0-9_.-]+|\1<token>|g' -e 's/[0-9a-f]{12}/<id>/g' -e 's/[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z/<ts>/g' -e 's/(token   : ).*/\1<token>/g' -e 's|/tmp/tmp\.[A-Za-z0-9]+|<tmpdir>|g'"

echo "### 1. grant a 3-second lease for the deploy command"
GRANT_OUT=$(node "$ROOT/leaseguard.js" grant "echo deploy-*" --for 3s --note "demo lease")
printf '%s\n' "$GRANT_OUT" | eval "$NORM"
TOKEN=$(printf '%s\n' "$GRANT_OUT" | sed -n 's/.*token   : //p')

echo ""
echo "### 2. run it right away -> allowed"
node "$ROOT/leaseguard.js" run --lease "$TOKEN" -- echo deploy-backend

echo ""
echo "### 3. run it again after the lease expired -> denied"
sleep 4
node "$ROOT/leaseguard.js" run --lease "$TOKEN" -- echo deploy-backend 2>&1 | eval "$NORM" || true

echo ""
echo "### 4. audit: the stale approval died quietly, nothing ran on it"
node "$ROOT/leaseguard.js" audit | eval "$NORM"
