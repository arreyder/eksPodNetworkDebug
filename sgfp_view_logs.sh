#!/usr/bin/env bash
set -euo pipefail

# Helper script to view pod-related log lines from a diagnostic bundle
# Usage: sgfp_view_logs.sh <bundle-dir> [options]

BUNDLE="${1:-}"
if [ -z "$BUNDLE" ]; then
  echo "Usage: $0 <sgfp_bundle_dir> [--errors-only] [--all-logs]" >&2
  echo "" >&2
  echo "Options:" >&2
  echo "  --errors-only    Show only error/warning lines" >&2
  echo "  --all-logs       Show all log lines (not just pod-related)" >&2
  echo "" >&2
  echo "Examples:" >&2
  echo "  $0 sgfp_bundle_pod-name_20251109_120830" >&2
  echo "  $0 sgfp_bundle_pod-name_20251109_120830 --errors-only" >&2
  exit 1
fi

if [ ! -d "$BUNDLE" ]; then
  echo "ERROR: Bundle directory does not exist: $BUNDLE" >&2
  exit 1
fi

# Parse options
ERRORS_ONLY=0
ALL_LOGS=0
shift
while [ $# -gt 0 ]; do
  case "$1" in
    --errors-only)
      ERRORS_ONLY=1
      shift
      ;;
    --all-logs)
      ALL_LOGS=1
      shift
      ;;
    *)
      echo "ERROR: Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

log()  { printf "[VIEW_LOGS] %s\n" "$*"; }
warn() { printf "[VIEW_LOGS] WARN: %s\n" "$*" >&2; }

POD_DIR=$(find "$BUNDLE" -maxdepth 1 -type d -name 'pod_*' | head -n1 || true)
NODE_DIR=$(find "$BUNDLE" -maxdepth 1 -type d -name 'node_*' | head -n1 || true)

if [ -z "$POD_DIR" ] || [ ! -d "$POD_DIR" ]; then
  warn "Pod directory not found in bundle: $BUNDLE"
  exit 1
fi

# Extract pod name from bundle
POD=$(basename "$BUNDLE" | sed 's/^sgfp_bundle_\(.*\)_[0-9]\{8\}_[0-9]\{6\}$/\1/')

log "Extracting pod identifiers from bundle..."

# Collect pod identifiers
POD_IP_FILE="$POD_DIR/pod_ip.txt"
POD_TIMING="$POD_DIR/pod_timing.txt"
POD_ENI_ID="$POD_DIR/pod_branch_eni_id.txt"
POD_FULL="$POD_DIR/pod_full.json"

POD_IP=$(grep "^POD_IP=" "$POD_IP_FILE" 2>/dev/null | cut -d= -f2- || echo "")
POD_UID=$(grep "^UID=" "$POD_TIMING" 2>/dev/null | cut -d= -f2- || echo "")
ENI_ID=$(cat "$POD_ENI_ID" 2>/dev/null | tr -d '[:space:]' || echo "")

# Extract container ID from pod status
CONTAINER_ID=""
if [ -s "$POD_FULL" ]; then
  CONTAINER_ID=$(jq -r '.status.containerStatuses[]? | select(.name | test("POD|infra|pause")) | .containerID // empty' "$POD_FULL" 2>/dev/null | head -1 || echo "")
  if [ -z "$CONTAINER_ID" ] || [ "$CONTAINER_ID" = "null" ] || [ "$CONTAINER_ID" = "" ]; then
    CONTAINER_ID=$(jq -r '.status.containerStatuses[0]? | .containerID // empty' "$POD_FULL" 2>/dev/null | head -1 || echo "")
  fi
  # Remove container runtime prefix
  if [ -n "$CONTAINER_ID" ] && [ "$CONTAINER_ID" != "null" ] && [ "$CONTAINER_ID" != "" ]; then
    CONTAINER_ID=$(echo "$CONTAINER_ID" | sed 's|^[^:]*://||' || echo "$CONTAINER_ID")
  fi
fi

# Short container ID (first 12 chars)
CONTAINER_ID_SHORT=""
if [ -n "$CONTAINER_ID" ] && [ "$CONTAINER_ID" != "null" ] && [ "$CONTAINER_ID" != "" ]; then
  CONTAINER_ID_SHORT=$(echo "$CONTAINER_ID" | head -c 12 || echo "")
fi

# Build search patterns
SEARCH_PATTERNS=()
[ -n "$POD" ] && SEARCH_PATTERNS+=("$POD")
[ -n "$CONTAINER_ID" ] && SEARCH_PATTERNS+=("$CONTAINER_ID")
[ -n "$CONTAINER_ID_SHORT" ] && SEARCH_PATTERNS+=("$CONTAINER_ID_SHORT")
[ -n "$ENI_ID" ] && SEARCH_PATTERNS+=("$ENI_ID")
[ -n "$POD_IP" ] && SEARCH_PATTERNS+=("$POD_IP")
[ -n "$POD_UID" ] && SEARCH_PATTERNS+=("$POD_UID")

if [ ${#SEARCH_PATTERNS[@]} -eq 0 ]; then
  warn "No pod identifiers found in bundle"
  exit 1
fi

log "Search patterns: ${SEARCH_PATTERNS[*]}"

# Generate grep pattern (escape special characters)
GREP_PATTERN=$(printf '%s\n' "${SEARCH_PATTERNS[@]}" | sed 's/[[\.*^$()+?{|]/\\&/g' | tr '\n' '|' | sed 's/|$//')

# Build grep command
if [ "$ALL_LOGS" -eq 1 ]; then
  # Show all log lines, not filtered
  USE_GREP=0
elif [ "$ERRORS_ONLY" -eq 1 ]; then
  # Show only error/warning lines that match patterns
  USE_GREP=1
  ERROR_PATTERN="(error|warn|fail|fatal|panic|timeout|throttle)"
  GREP_ARGS="-iE \"($ERROR_PATTERN).*($GREP_PATTERN)|($GREP_PATTERN).*($ERROR_PATTERN)\""
else
  # Show lines matching pod patterns
  USE_GREP=1
  GREP_ARGS="-iE \"$GREP_PATTERN\""
fi

echo ""
echo "=== Pod-Related Log Lines ==="
echo "Pod: $POD"
[ -n "$POD_IP" ] && echo "IP: $POD_IP"
[ -n "$ENI_ID" ] && echo "ENI: $ENI_ID"
[ -n "$CONTAINER_ID_SHORT" ] && echo "Container ID: ${CONTAINER_ID_SHORT}..."
echo ""

FOUND_ANY=0

# Search aws-node logs
AWS_NODE_ERRORS="$POD_DIR/aws_node_errors.log"
AWS_NODE_LOG_POD="$POD_DIR/aws_node_full.log"

if [ "$ERRORS_ONLY" -eq 1 ] && [ -s "$AWS_NODE_ERRORS" ]; then
  echo "--- aws-node errors ---"
  cat "$AWS_NODE_ERRORS"
  echo ""
  FOUND_ANY=1
elif [ -s "$AWS_NODE_LOG_POD" ]; then
  if [ "$ALL_LOGS" -eq 1 ]; then
    echo "--- aws-node full log ---"
    cat "$AWS_NODE_LOG_POD"
    FOUND_ANY=1
  elif [ "$USE_GREP" -eq 1 ]; then
    MATCHES=$(eval "grep $GREP_ARGS \"$AWS_NODE_LOG_POD\"" 2>/dev/null || true)
    if [ -n "$MATCHES" ]; then
      echo "--- aws-node log (pod-related) ---"
      echo "$MATCHES"
      FOUND_ANY=1
    fi
  fi
  echo ""
fi

# Search CNI logs
NODE_CNI_LOGS_DIR=""
if [ -n "$NODE_DIR" ]; then
  NODE_CNI_LOGS_DIR="$NODE_DIR/cni_logs"
fi

if [ -n "$NODE_CNI_LOGS_DIR" ] && [ -d "$NODE_CNI_LOGS_DIR" ]; then
  for LOG_FILE in "$NODE_CNI_LOGS_DIR"/*.log; do
    [ ! -f "$LOG_FILE" ] && continue
    LOG_NAME=$(basename "$LOG_FILE")
    ERROR_FILE="${LOG_FILE}.errors"
    
    if [ "$ERRORS_ONLY" -eq 1 ] && [ -f "$ERROR_FILE" ] && [ -s "$ERROR_FILE" ]; then
      # Check if error file has matches
      MATCHES=$(eval "grep -iE \"$GREP_PATTERN\" \"$ERROR_FILE\"" 2>/dev/null || true)
      if [ -n "$MATCHES" ]; then
        echo "--- $LOG_NAME errors (pod-related) ---"
        echo "$MATCHES"
        echo ""
        FOUND_ANY=1
      fi
    elif [ -s "$LOG_FILE" ]; then
      if [ "$ALL_LOGS" -eq 1 ]; then
        echo "--- $LOG_NAME (all lines) ---"
        cat "$LOG_FILE"
        echo ""
        FOUND_ANY=1
      elif [ "$USE_GREP" -eq 1 ]; then
        MATCHES=$(eval "grep $GREP_ARGS \"$LOG_FILE\"" 2>/dev/null || true)
        if [ -n "$MATCHES" ]; then
          echo "--- $LOG_NAME (pod-related) ---"
          echo "$MATCHES"
          echo ""
          FOUND_ANY=1
        fi
      fi
    fi
  done
fi

# Search node-level aws-node logs
NODE_AWS_LOG="${NODE_DIR:+$NODE_DIR/aws_node_full.log}"
if [ -n "$NODE_AWS_LOG" ] && [ -s "$NODE_AWS_LOG" ]; then
  if [ "$ALL_LOGS" -eq 1 ]; then
    echo "--- aws-node log (node-level, all lines) ---"
    cat "$NODE_AWS_LOG"
    echo ""
    FOUND_ANY=1
  elif [ "$USE_GREP" -eq 1 ]; then
    MATCHES=$(eval "grep $GREP_ARGS \"$NODE_AWS_LOG\"" 2>/dev/null || true)
    if [ -n "$MATCHES" ]; then
      echo "--- aws-node log (node-level, pod-related) ---"
      echo "$MATCHES"
      echo ""
      FOUND_ANY=1
    fi
  fi
fi

if [ "$FOUND_ANY" -eq 0 ] && [ "$ALL_LOGS" -eq 0 ]; then
  echo "No pod-related log lines found."
  echo ""
  echo "Try:"
  echo "  $0 $BUNDLE --all-logs    # Show all log lines"
  echo "  $0 $BUNDLE --errors-only # Show only error lines"
fi

