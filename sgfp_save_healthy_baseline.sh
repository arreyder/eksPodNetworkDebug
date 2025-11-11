#!/usr/bin/env bash
# Save healthy pod diagnostic bundle as a baseline for comparison
# Usage: ./sgfp_save_healthy_baseline.sh <bundle-dir> [--label <label>]

set -euo pipefail

BUNDLE_DIR="${1:?usage: sgfp_save_healthy_baseline.sh <bundle-dir> [--label <label>]}"
LABEL="${3:-healthy}"

if [ "$1" = "--label" ] && [ -n "${2:-}" ]; then
  LABEL="$2"
  BUNDLE_DIR="${3:?usage: sgfp_save_healthy_baseline.sh <bundle-dir> [--label <label>]}"
fi

if [ ! -d "$BUNDLE_DIR" ]; then
  echo "[ERROR] Bundle directory not found: $BUNDLE_DIR" >&2
  exit 1
fi

# Helper function to get kubectl context
get_kubectl_context() {
  local context
  if command -v kubectl >/dev/null 2>&1; then
    context=$(kubectl config current-context 2>/dev/null || echo "unknown")
  else
    context="unknown"
  fi
  echo "$context" | sed 's/[^a-zA-Z0-9._-]/-/g' | sed 's/^-\+//;s/-\+$//' | sed 's/-\+/-/g'
}

KUBECTL_CONTEXT=$(get_kubectl_context)
BASELINE_DIR="baselines/${KUBECTL_CONTEXT}/healthy-pods"
mkdir -p "$BASELINE_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="$BASELINE_DIR/${LABEL}_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

log()  { printf "[HEALTHY-BASELINE] %s\n" "$*"; }

log "Saving healthy pod baseline"
log "Bundle: $BUNDLE_DIR"
log "Output: $OUTPUT_DIR"
log "Label: $LABEL"

# Extract pod name from bundle directory
POD_NAME=$(basename "$BUNDLE_DIR" | sed 's/.*_\([^_]*\)_\([^_]*\)_\([^_]*\)_.*/\1-\2-\3/' | head -1 || echo "unknown")
if [ "$POD_NAME" = "unknown" ]; then
  # Try alternative pattern
  POD_NAME=$(basename "$BUNDLE_DIR" | grep -oE '[a-z0-9-]+-[a-z0-9]+' | head -1 || echo "unknown")
fi

# Find pod directory in bundle
POD_DIR=$(find "$BUNDLE_DIR" -type d -name "pod_*" | head -1)
if [ -z "$POD_DIR" ]; then
  echo "[ERROR] Could not find pod directory in bundle" >&2
  exit 1
fi

# Extract pod name from directory
ACTUAL_POD_NAME=$(basename "$POD_DIR" | sed 's/^pod_//')

log "Pod: $ACTUAL_POD_NAME"

# 1) Create normalized JSON summary (for easy comparison)
log "Creating normalized JSON summary..."
if command -v jq >/dev/null 2>&1; then
  # Extract key diagnostic information into normalized format
  if ./sgfp_extract_normalized.sh "$BUNDLE_DIR" > "$OUTPUT_DIR/normalized.json" 2>&1; then
    log "Normalized JSON created successfully"
  else
    log "WARN: Failed to create normalized JSON (check extraction script output above)" >&2
    # Try to show what went wrong
    if [ ! -s "$OUTPUT_DIR/normalized.json" ]; then
      log "WARN: normalized.json is empty - extraction may have failed" >&2
    fi
  fi
else
  echo "[WARN] jq not available, skipping normalized JSON" >&2
fi

# 2) Copy key files for reference
log "Copying key diagnostic files..."
mkdir -p "$OUTPUT_DIR/reference"

# Copy report
if [ -f "$BUNDLE_DIR/report.md" ]; then
  cp "$BUNDLE_DIR/report.md" "$OUTPUT_DIR/reference/" 2>/dev/null || true
fi

# Copy pod snapshot
if [ -f "$BUNDLE_DIR/cluster_pod_snapshot.json" ]; then
  cp "$BUNDLE_DIR/cluster_pod_snapshot.json" "$OUTPUT_DIR/reference/" 2>/dev/null || true
fi

# Copy key pod files
if [ -d "$POD_DIR" ]; then
  mkdir -p "$OUTPUT_DIR/reference/pod"
  for file in pod_annotations.json pod_conditions.json pod_ip.txt pod_timing.txt pod_eni_readiness.txt pod_branch_eni_sgs_rules.json; do
    if [ -f "$POD_DIR/$file" ]; then
      cp "$POD_DIR/$file" "$OUTPUT_DIR/reference/pod/" 2>/dev/null || true
    fi
  done
fi

# Copy node completeness data
NODE_DIR=$(find "$BUNDLE_DIR" -type d -name "node_*" | head -1)
if [ -d "$NODE_DIR" ]; then
  mkdir -p "$OUTPUT_DIR/reference/node"
  if [ -f "$NODE_DIR/node_netns_details.json" ]; then
    cp "$NODE_DIR/node_netns_details.json" "$OUTPUT_DIR/reference/node/" 2>/dev/null || true
  fi
fi

# 3) Create metadata
cat > "$OUTPUT_DIR/metadata.json" <<EOF
{
  "pod_name": "$ACTUAL_POD_NAME",
  "cluster": "$KUBECTL_CONTEXT",
  "label": "$LABEL",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "source_bundle": "$(basename "$BUNDLE_DIR")",
  "source_bundle_path": "$BUNDLE_DIR"
}
EOF

# 4) Create symlink to latest
LATEST_LINK="$BASELINE_DIR/${LABEL}_latest"
rm -f "$LATEST_LINK" 2>/dev/null || true
ln -s "$(basename "$OUTPUT_DIR")" "$LATEST_LINK" 2>/dev/null || true

log "Done. Baseline saved to: $OUTPUT_DIR"
log "Latest link: $LATEST_LINK -> $OUTPUT_DIR"
log ""
log "To compare with an unhealthy pod:"
log "  ./sgfp_compare_pod_baseline.sh <unhealthy-bundle-dir> $OUTPUT_DIR"

