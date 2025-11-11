#!/usr/bin/env bash
set -euo pipefail

# Helper function to get kubectl context and sanitize for directory names
get_kubectl_context() {
  local context
  if command -v kubectl >/dev/null 2>&1; then
    context=$(kubectl config current-context 2>/dev/null || echo "unknown")
  else
    context="unknown"
  fi
  # Sanitize: replace special chars with dashes, remove leading/trailing dashes
  echo "$context" | sed 's/[^a-zA-Z0-9._-]/-/g' | sed 's/^-\+//;s/-\+$//' | sed 's/-\+/-/g'
}

NS="default"
POD=""
MINUTES=$((2*24*60))
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
SKIP_API=0
API_DIR=""
MARK_HEALTHY=0
MARK_UNHEALTHY=0

KUBECTL_CONTEXT=$(get_kubectl_context)
DATA_DIR="data/${KUBECTL_CONTEXT}"
REPORTS_DIR="reports/${KUBECTL_CONTEXT}"
mkdir -p "$DATA_DIR" "$REPORTS_DIR"

usage(){ echo "Usage: $0 <pod> [-n ns] [--minutes N|--days D] [--region R] [--skip-api] [--api-dir DIR] [--mark-healthy] [--mark-unhealthy]"; }

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
    --mark-healthy) MARK_HEALTHY=1; shift ;;
    --mark-unhealthy) MARK_UNHEALTHY=1; shift ;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1"; usage; exit 1;;
  esac
done

need(){ command -v "$1" >/dev/null 2>&1 || { echo "[DOCTOR] ERROR: Missing dependency: $1"; exit 1; }; }
need kubectl; need jq; need awk; need grep

# Check if baseline comparison is requested
BASELINE_COMPARE=0
BASELINE_OLD_DIR=""
if [ -n "${SGFP_BASELINE_DIR:-}" ] && [ -d "$SGFP_BASELINE_DIR" ]; then
  BASELINE_COMPARE=1
  BASELINE_OLD_DIR="$SGFP_BASELINE_DIR"
  echo "[DOCTOR] Baseline comparison enabled: $BASELINE_OLD_DIR"
  echo "[DOCTOR] Will capture incident baseline snapshot and compare metrics"
fi

echo "[DOCTOR] Cluster: ${KUBECTL_CONTEXT}"
[ "$MARK_HEALTHY" -eq 1 ] && echo "[DOCTOR] Will mark collection as HEALTHY and save as baseline"
[ "$MARK_UNHEALTHY" -eq 1 ] && echo "[DOCTOR] Will mark collection as UNHEALTHY"
echo "[DOCTOR] [1/6] Collecting diagnostics for pod '$POD' in ns '$NS'..."
COLLECT_ARGS=(-n "$NS")
[ "$MARK_HEALTHY" -eq 1 ] && COLLECT_ARGS+=("--mark-healthy")
[ "$MARK_UNHEALTHY" -eq 1 ] && COLLECT_ARGS+=("--mark-unhealthy")
if ! ./sgfp_collect.sh "${COLLECT_ARGS[@]}" "$POD" 2>&1; then
  echo "[DOCTOR] WARN: Collection had errors, but continuing..." >&2
fi
BUNDLE_DIR="$(ls -dt "$DATA_DIR"/sgfp_bundle_* 2>/dev/null | head -1 || true)"
[ -n "$BUNDLE_DIR" ] && [ -d "$BUNDLE_DIR" ] || { echo "[DOCTOR] ERROR: Failed to collect bundle." >&2; exit 1; }
echo "[DOCTOR] Bundle: $BUNDLE_DIR"

# Capture incident baseline snapshot if comparison is enabled
if [ "$BASELINE_COMPARE" -eq 1 ]; then
  echo "[DOCTOR] [1.5/6] Capturing incident baseline snapshot for metrics comparison..."
  if ./sgfp_baseline_capture.sh --label incident 2>&1; then
    BASELINE_INCIDENT_DIR="$(ls -dt "$DATA_DIR"/sgfp_baseline_incident_* 2>/dev/null | head -1 || true)"
    if [ -n "$BASELINE_INCIDENT_DIR" ] && [ -d "$BASELINE_INCIDENT_DIR" ]; then
      echo "[DOCTOR] Incident baseline: $BASELINE_INCIDENT_DIR"
      # Copy incident baseline into bundle for reference
      mkdir -p "$BUNDLE_DIR/incident_baseline"
      cp -r "$BASELINE_INCIDENT_DIR"/* "$BUNDLE_DIR/incident_baseline/" 2>/dev/null || true
    fi
  else
    echo "[DOCTOR] WARN: Failed to capture incident baseline snapshot" >&2
  fi
fi

if [ -n "$API_DIR" ]; then
  [ -d "$API_DIR" ] || { echo "[DOCTOR] ERROR: --api-dir not found: $API_DIR"; exit 1; }
  API_USED_DIR="$API_DIR"
  echo "[DOCTOR] [2/6] Using provided API diag: $API_USED_DIR"
elif [ "$SKIP_API" -eq 1 ]; then
  echo "[DOCTOR] [2/6] Skipping API diagnostics."
  API_USED_DIR="$(ls -dt "$DATA_DIR"/sgfp_api_diag_* 2>/dev/null | head -1 || true)"
else
  echo "[DOCTOR] [2/6] Running API diagnostics (window: ${MINUTES}m$( [ -n "$REGION" ] && printf ", region: %s" "$REGION"))..."
  if [ -n "$REGION" ]; then WINDOW_MINUTES="$MINUTES" AWS_REGION="$REGION" ./sgfp_api_diag.sh || true
  else WINDOW_MINUTES="$MINUTES" ./sgfp_api_diag.sh || true; fi
  API_USED_DIR="$(ls -dt "$DATA_DIR"/sgfp_api_diag_* 2>/dev/null | head -1 || true)"
  [ -n "$API_USED_DIR" ] && echo "[DOCTOR] API diag: $API_USED_DIR"
fi

echo "[DOCTOR] [3/6] Generating report..."
if ! ./sgfp_report.sh "$BUNDLE_DIR" "$REPORTS_DIR" 2>&1; then
  echo "[DOCTOR] WARN: Report generation had errors" >&2
fi
# Copy report to reports directory
REPORT_FILE="$BUNDLE_DIR/report.md"
if [ -f "$REPORT_FILE" ]; then
  cp "$REPORT_FILE" "$REPORTS_DIR/$(basename "$BUNDLE_DIR").md" 2>/dev/null || true
  REPORT_FILE="$REPORTS_DIR/$(basename "$BUNDLE_DIR").md"
else
  echo "[DOCTOR] WARN: Report file not found" >&2
fi

echo "[DOCTOR] [4/6] Running analysis..."
if ! ./sgfp_post_analyze.sh "$BUNDLE_DIR" 2>&1; then
  echo "[DOCTOR] WARN: Analysis had errors" >&2
fi

echo "[DOCTOR] [5/6] Running connectivity analysis..."
if ! ./sgfp_analyze_connectivity.sh "$BUNDLE_DIR" 2>&1; then
  echo "[DOCTOR] WARN: Connectivity analysis had errors" >&2
fi

# Run metrics comparison if baseline is available
if [ "$BASELINE_COMPARE" -eq 1 ] && [ -n "$BASELINE_OLD_DIR" ]; then
  BASELINE_INCIDENT_DIR="$(ls -dt "$DATA_DIR"/sgfp_baseline_incident_* 2>/dev/null | head -1 || true)"
  if [ -n "$BASELINE_INCIDENT_DIR" ] && [ -d "$BASELINE_INCIDENT_DIR" ]; then
    echo "[DOCTOR] [5.5/6] Analyzing metrics differences..."
    if ./sgfp_analyze_metrics_diff.sh "$BASELINE_OLD_DIR" "$BASELINE_INCIDENT_DIR" > "$BUNDLE_DIR/metrics_comparison.txt" 2>&1; then
      echo "[DOCTOR] Metrics comparison saved to: $BUNDLE_DIR/metrics_comparison.txt"
      # Regenerate report to include metrics comparison
      echo "[DOCTOR] Regenerating report with metrics comparison..."
      ./sgfp_report.sh "$BUNDLE_DIR" >/dev/null 2>&1 || true
    else
      echo "[DOCTOR] WARN: Metrics comparison had errors" >&2
    fi
  fi
fi

echo "[DOCTOR] [6/6] Displaying report..."
if [ -f "$REPORT_FILE" ]; then
  echo
  cat "$REPORT_FILE"
  echo
else
  echo "[DOCTOR] WARN: Report file not found: $REPORT_FILE"
fi

echo "[DOCTOR] Output locations:"
echo "[DOCTOR]   Cluster: ${KUBECTL_CONTEXT}"
echo "[DOCTOR]   Bundle: $BUNDLE_DIR"
[ -n "$API_USED_DIR" ] && echo "[DOCTOR]   API diag: $API_USED_DIR"
[ -f "$REPORT_FILE" ] && echo "[DOCTOR]   Report: $REPORT_FILE"
echo ""
echo "[DOCTOR] Network capture:"
echo "[DOCTOR]   To capture network traffic for this pod, run:"
echo "[DOCTOR]   ./sgfp_pod_tcpdump.sh $POD $NS"
echo "[DOCTOR]   Or with custom tcpdump arguments:"
echo "[DOCTOR]   ./sgfp_pod_tcpdump.sh $POD $NS \"-i any -n -v port 6000\""
echo "[DOCTOR] Done."
