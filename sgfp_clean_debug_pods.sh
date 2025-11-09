#!/usr/bin/env bash
set -euo pipefail

NS="${1:-default}"

echo "Finding debug pods in namespace '$NS'..."
DEBUG_PODS=$(kubectl -n "$NS" get pods -o name 2>/dev/null | grep -E "(node-debugger|debugger-)" || true)

if [ -z "$DEBUG_PODS" ]; then
  echo "No debug pods found in namespace '$NS'"
  exit 0
fi

echo "Found $(echo "$DEBUG_PODS" | wc -l | tr -d '[:space:]') debug pod(s):"
echo "$DEBUG_PODS" | sed 's|^pod/|  - |'
echo ""

DELETED=0
SKIPPED=0

while IFS= read -r pod_line; do
  [ -z "$pod_line" ] && continue
  pod_name="${pod_line#pod/}"
  echo "Debug pod: $pod_name"
  read -p "Delete $pod_name? [y/N] " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    if kubectl -n "$NS" delete pod "$pod_name" >/dev/null 2>&1; then
      echo "[OK] Deleted $pod_name"
      DELETED=$((DELETED + 1))
    else
      echo "[ERROR] Failed to delete $pod_name"
    fi
  else
    echo "[SKIP] Skipped $pod_name"
    SKIPPED=$((SKIPPED + 1))
  fi
done <<EOF
$DEBUG_PODS
EOF

echo ""
echo "Summary: $DELETED deleted, $SKIPPED skipped"

