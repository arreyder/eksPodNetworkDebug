#!/usr/bin/env bash
set -euo pipefail

NS="default"
POD=""
MINUTES=$((2*24*60))
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
SKIP_API=0
API_DIR=""

usage(){ echo "Usage: $0 <pod> [-n ns] [--minutes N|--days D] [--region R] [--skip-api] [--api-dir DIR]"; }

[ $# -lt 1 ] && { usage; exit 1; }
POD="$1"; shift
while [ $# -gt 0 ]; do
  case "$1" in
    -n|--namespace) NS="${2:?}"; shift 2;;
    --minutes) MINUTES="${2:?}"; shift 2;;
    --days) MINUTES=$(( ${2:?} * 24 * 60 )); shift 2;;
    --region) REGION="${2:?}"; shift 2;;
    --skip-api) SKIP_API=1; shift ;;
    --api-dir) API_DIR="${2:?}"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1"; usage; exit 1;;
  esac
done

need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1"; exit 1; }; }
need kubectl; need jq; need awk; need grep

echo "[1/4] Collecting diagnostics for pod '$POD' in ns '$NS'..."
./sgfp_collect.sh -n "$NS" "$POD" >/dev/null || true
BUNDLE_DIR="$(ls -dt sgfp_bundle_* 2>/dev/null | head -1 || true)"
[ -n "$BUNDLE_DIR" ] || { echo "Failed to collect bundle."; exit 1; }
echo "Bundle: $BUNDLE_DIR"

if [ -n "$API_DIR" ]; then
  [ -d "$API_DIR" ] || { echo "--api-dir not found: $API_DIR"; exit 1; }
  API_USED_DIR="$API_DIR"
  echo "[2/4] Using provided API diag: $API_USED_DIR"
elif [ "$SKIP_API" -eq 1 ]; then
  echo "[2/4] Skipping API diagnostics."
  API_USED_DIR="$(ls -dt sgfp_api_diag_* 2>/dev/null | head -1 || true)"
else
  echo "[2/4] Running API diagnostics (window: ${MINUTES}m$( [ -n "$REGION" ] && printf ", region: %s" "$REGION"))..."
  if [ -n "$REGION" ]; then WINDOW_MINUTES="$MINUTES" AWS_REGION="$REGION" ./sgfp_api_diag.sh >/dev/null || true
  else WINDOW_MINUTES="$MINUTES" ./sgfp_api_diag.sh >/dev/null || true; fi
  API_USED_DIR="$(ls -dt sgfp_api_diag_* 2>/dev/null | head -1 || true)"
  echo "API diag: $API_USED_DIR"
fi

echo "[3/4] Generating report..."
./sgfp_report.sh "$BUNDLE_DIR" >/dev/null || true
REPORT_FILE="$BUNDLE_DIR/report.md"
[ -f "$REPORT_FILE" ] && echo "Report: $REPORT_FILE"

echo "[4/4] Summary"
POD_DIR=$(find "$BUNDLE_DIR" -maxdepth 1 -type d -name 'pod_*' | head -n1 || true)
NODE_DIR=$(find "$BUNDLE_DIR" -maxdepth 1 -type d -name 'node_*' | head -n1 || true)

has_podeni="NO"
if [ -s "$POD_DIR/pod_annotations.json" ] && jq -er '."vpc.amazonaws.com/pod-eni"' "$POD_DIR/pod_annotations.json" >/dev/null 2>&1; then
  has_podeni="YES"
fi

routing="UNKNOWN"
if [ -s "$POD_DIR/pod_netns_routes_rules.txt" ] && grep -Eq 'table (100|101)' "$POD_DIR/pod_netns_routes_rules.txt"; then
  routing="PRESENT"; else routing="MISSING"; fi

pct="n/a"
if [ -s "$NODE_DIR/node_conntrack_mtu.txt" ]; then
  pair="$(grep -Eo '[0-9]+\s*/\s*[0-9]+' "$NODE_DIR/node_conntrack_mtu.txt" | head -1 || true)"
  if [ -n "$pair" ]; then
    CT="$(printf '%s' "$pair" | awk -F'/' '{gsub(/ /,"",$1); print $1}')"
    MX="$(printf '%s' "$pair" | awk -F'/' '{gsub(/ /,"",$2); print $2}')"
    if printf '%s' "$CT" | grep -Eq '^[0-9]+$' && printf '%s' "$MX" | grep -Eq '^[0-9]+$' && [ "$MX" -gt 0 ]; then
      pct="$(awk -v c="$CT" -v m="$MX" 'BEGIN{printf "%d%%", (100*c)/m}')"
    fi
  fi
fi

echo
[ "$has_podeni" = "YES" ] && echo "✓ Pod ENI annotation present (SG-for-Pods)" || echo "• No Pod ENI annotation detected"
[ "$routing" = "PRESENT" ] && echo "✓ Per-pod routing tables present (100/101)" || echo "• Per-pod routing tables not detected"
[ "$pct" != "n/a" ] && echo "✓ Conntrack usage: $pct" || echo "• Conntrack usage unavailable"
[ -n "$API_USED_DIR" ] && [ -f "$API_USED_DIR/throttle_by_action.txt" ] && head -n1 "$API_USED_DIR/throttle_by_action.txt" | sed 's/^/• Throttling sample: /' || echo "✓ No throttling summary available"
echo
echo "Bundle:  $BUNDLE_DIR"
[ -n "$API_USED_DIR" ] && echo "API diag: $API_USED_DIR"
[ -f "$REPORT_FILE" ] && echo "Report:  $REPORT_FILE"
echo
echo "Done."
