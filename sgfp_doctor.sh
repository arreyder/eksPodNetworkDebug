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

need(){ command -v "$1" >/dev/null 2>&1 || { echo "[DOCTOR] ERROR: Missing dependency: $1"; exit 1; }; }
need kubectl; need jq; need awk; need grep

echo "[DOCTOR] [1/6] Collecting diagnostics for pod '$POD' in ns '$NS'..."
if ! ./sgfp_collect.sh -n "$NS" "$POD" 2>&1; then
  echo "[DOCTOR] WARN: Collection had errors, but continuing..." >&2
fi
BUNDLE_DIR="$(ls -dt sgfp_bundle_* 2>/dev/null | head -1 || true)"
[ -n "$BUNDLE_DIR" ] && [ -d "$BUNDLE_DIR" ] || { echo "[DOCTOR] ERROR: Failed to collect bundle." >&2; exit 1; }
echo "[DOCTOR] Bundle: $BUNDLE_DIR"

if [ -n "$API_DIR" ]; then
  [ -d "$API_DIR" ] || { echo "[DOCTOR] ERROR: --api-dir not found: $API_DIR"; exit 1; }
  API_USED_DIR="$API_DIR"
  echo "[DOCTOR] [2/6] Using provided API diag: $API_USED_DIR"
elif [ "$SKIP_API" -eq 1 ]; then
  echo "[DOCTOR] [2/6] Skipping API diagnostics."
  API_USED_DIR="$(ls -dt sgfp_api_diag_* 2>/dev/null | head -1 || true)"
else
  echo "[DOCTOR] [2/6] Running API diagnostics (window: ${MINUTES}m$( [ -n "$REGION" ] && printf ", region: %s" "$REGION"))..."
  if [ -n "$REGION" ]; then WINDOW_MINUTES="$MINUTES" AWS_REGION="$REGION" ./sgfp_api_diag.sh >/dev/null || true
  else WINDOW_MINUTES="$MINUTES" ./sgfp_api_diag.sh >/dev/null || true; fi
  API_USED_DIR="$(ls -dt sgfp_api_diag_* 2>/dev/null | head -1 || true)"
  [ -n "$API_USED_DIR" ] && echo "[DOCTOR] API diag: $API_USED_DIR"
fi

echo "[DOCTOR] [3/6] Generating report..."
if ! ./sgfp_report.sh "$BUNDLE_DIR" 2>&1; then
  echo "[DOCTOR] WARN: Report generation had errors" >&2
fi
REPORT_FILE="$BUNDLE_DIR/report.md"
[ -f "$REPORT_FILE" ] || echo "[DOCTOR] WARN: Report file not found" >&2

echo "[DOCTOR] [4/6] Running analysis..."
if ! ./sgfp_post_analyze.sh "$BUNDLE_DIR" 2>&1; then
  echo "[DOCTOR] WARN: Analysis had errors" >&2
fi

echo "[DOCTOR] [5/6] Running connectivity analysis..."
if ! ./sgfp_analyze_connectivity.sh "$BUNDLE_DIR" 2>&1; then
  echo "[DOCTOR] WARN: Connectivity analysis had errors" >&2
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
echo "[DOCTOR]   Bundle: $BUNDLE_DIR"
[ -n "$API_USED_DIR" ] && echo "[DOCTOR]   API diag: $API_USED_DIR"
[ -f "$REPORT_FILE" ] && echo "[DOCTOR]   Report: $REPORT_FILE"
echo "[DOCTOR] Done."
