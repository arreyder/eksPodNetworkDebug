#!/usr/bin/env bash
# Compare unhealthy pod diagnostic bundle with healthy pod baseline
# Usage: ./sgfp_compare_pod_baseline.sh <unhealthy-bundle-dir> <healthy-baseline-dir>

set -euo pipefail

UNHEALTHY_BUNDLE="${1:?usage: sgfp_compare_pod_baseline.sh <unhealthy-bundle-dir> <healthy-baseline-dir>}"
HEALTHY_BASELINE="${2:?usage: sgfp_compare_pod_baseline.sh <unhealthy-bundle-dir> <healthy-baseline-dir>}"

if [ ! -d "$UNHEALTHY_BUNDLE" ]; then
  echo "[ERROR] Unhealthy bundle directory not found: $UNHEALTHY_BUNDLE" >&2
  exit 1
fi

if [ ! -d "$HEALTHY_BASELINE" ]; then
  echo "[ERROR] Healthy baseline directory not found: $HEALTHY_BASELINE" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "[ERROR] jq is required for comparison" >&2
  exit 1
fi

log() { printf "[COMPARE] %s\n" "$*"; }

log "Comparing unhealthy pod with healthy baseline"
log "Unhealthy bundle: $UNHEALTHY_BUNDLE"
log "Healthy baseline: $HEALTHY_BASELINE"
echo ""

# Extract normalized data
UNHEALTHY_NORM=$(mktemp)
HEALTHY_NORM=$(mktemp)

log "Extracting normalized data..."
./sgfp_extract_normalized.sh "$UNHEALTHY_BUNDLE" > "$UNHEALTHY_NORM" 2>/dev/null || {
  echo "[ERROR] Failed to extract normalized data from unhealthy bundle" >&2
  exit 1
}

if [ -f "$HEALTHY_BASELINE/normalized.json" ]; then
  cp "$HEALTHY_BASELINE/normalized.json" "$HEALTHY_NORM"
else
  # Try to extract from source bundle if available
  SOURCE_BUNDLE=$(jq -r '.metadata.source_bundle_path // ""' "$HEALTHY_BASELINE/metadata.json" 2>/dev/null || echo "")
  if [ -n "$SOURCE_BUNDLE" ] && [ -d "$SOURCE_BUNDLE" ]; then
    ./sgfp_extract_normalized.sh "$SOURCE_BUNDLE" > "$HEALTHY_NORM" 2>/dev/null || {
      echo "[ERROR] Failed to extract normalized data from healthy baseline" >&2
      exit 1
    }
  else
    echo "[ERROR] Could not find normalized data in healthy baseline" >&2
    exit 1
  fi
fi

# Create comparison output
OUTPUT_DIR="comparison_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

log "Generating comparison report..."
log "Output: $OUTPUT_DIR"

# Generate comparison JSON
jq -n \
  --slurpfile unhealthy "$UNHEALTHY_NORM" \
  --slurpfile healthy "$HEALTHY_NORM" \
  '{
    "comparison": {
      "unhealthy": $unhealthy[0],
      "healthy": $healthy[0],
      "differences": {
        "pod": {
          "phase": (if $unhealthy[0].pod.phase != $healthy[0].pod.phase then {"unhealthy": $unhealthy[0].pod.phase, "healthy": $healthy[0].pod.phase} else null end),
          "ready": (if $unhealthy[0].pod.ready != $healthy[0].pod.ready then {"unhealthy": $unhealthy[0].pod.ready, "healthy": $healthy[0].pod.ready} else null end),
          "containers_ready": (if $unhealthy[0].pod.containers_ready != $healthy[0].pod.containers_ready then {"unhealthy": $unhealthy[0].pod.containers_ready, "healthy": $healthy[0].pod.containers_ready} else null end)
        },
        "eni": {
          "readiness": {
            "ready_for_traffic": (if ($unhealthy[0].eni.readiness.ReadyForTraffic // "false") != ($healthy[0].eni.readiness.ReadyForTraffic // "false") then {"unhealthy": ($unhealthy[0].eni.readiness.ReadyForTraffic // "false"), "healthy": ($healthy[0].eni.readiness.ReadyForTraffic // "false")} else null end),
            "status": (if ($unhealthy[0].eni.readiness.Status // "") != ($healthy[0].eni.readiness.Status // "") then {"unhealthy": ($unhealthy[0].eni.readiness.Status // ""), "healthy": ($healthy[0].eni.readiness.Status // "")} else null end),
            "interface_type": (if ($unhealthy[0].eni.readiness.InterfaceType // "") != ($healthy[0].eni.readiness.InterfaceType // "") then {"unhealthy": ($unhealthy[0].eni.readiness.InterfaceType // ""), "healthy": ($healthy[0].eni.readiness.InterfaceType // "")} else null end)
          },
          "security_groups": {
            "ingress_rules": (if $unhealthy[0].eni.security_group_rules.ingress_count != $healthy[0].eni.security_group_rules.ingress_count then {"unhealthy": $unhealthy[0].eni.security_group_rules.ingress_count, "healthy": $healthy[0].eni.security_group_rules.ingress_count} else null end),
            "egress_rules": (if $unhealthy[0].eni.security_group_rules.egress_count != $healthy[0].eni.security_group_rules.egress_count then {"unhealthy": $unhealthy[0].eni.security_group_rules.egress_count, "healthy": $healthy[0].eni.security_group_rules.egress_count} else null end)
          }
        },
        "network_namespace": {
          "default_route": (if ($unhealthy[0].network_namespace.completeness.default_route // "") != ($healthy[0].network_namespace.completeness.default_route // "") then {"unhealthy": ($unhealthy[0].network_namespace.completeness.default_route // ""), "healthy": ($healthy[0].network_namespace.completeness.default_route // "")} else null end),
          "eth0_state": (if ($unhealthy[0].network_namespace.completeness.eth0_state // "") != ($healthy[0].network_namespace.completeness.eth0_state // "") then {"unhealthy": ($unhealthy[0].network_namespace.completeness.eth0_state // ""), "healthy": ($healthy[0].network_namespace.completeness.eth0_state // "")} else null end),
          "route_count": (if ($unhealthy[0].network_namespace.completeness.route_count // 0) != ($healthy[0].network_namespace.completeness.route_count // 0) then {"unhealthy": ($unhealthy[0].network_namespace.completeness.route_count // 0), "healthy": ($healthy[0].network_namespace.completeness.route_count // 0)} else null end)
        },
        "status_summary": {
          "healthy": (if $unhealthy[0].status_summary.healthy != $healthy[0].status_summary.healthy then {"unhealthy": $unhealthy[0].status_summary.healthy, "healthy": $healthy[0].status_summary.healthy} else null end)
        }
      }
    }
  }' > "$OUTPUT_DIR/comparison.json"

# Generate human-readable report
{
  echo "# Pod Diagnostic Comparison Report"
  echo ""
  echo "**Unhealthy Pod:** $(jq -r '.comparison.unhealthy.metadata.pod_name' "$OUTPUT_DIR/comparison.json")"
  echo "**Healthy Baseline:** $(jq -r '.comparison.healthy.metadata.pod_name' "$OUTPUT_DIR/comparison.json")"
  echo ""
  echo "Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
  echo ""
  echo "## Key Differences"
  echo ""
  
  # Check each difference category
  DIFFS=$(jq -r '.comparison.differences | to_entries[] | select(.value != null) | .key' "$OUTPUT_DIR/comparison.json")
  
  if [ -z "$DIFFS" ]; then
    echo "✅ **No significant differences found**"
    echo ""
    echo "The unhealthy pod appears to have similar configuration to the healthy baseline."
  else
    echo "$DIFFS" | while read -r category; do
      echo "### $(echo "$category" | sed 's/_/ /g' | awk '{for(i=1;i<=NF;i++)sub(/./,toupper(substr($i,1,1)),$i)}1')"
      echo ""
      jq -r --arg cat "$category" '.comparison.differences[$cat] | to_entries[] | select(.value != null) | "- **\(.key)**: Unhealthy=`\(.value.unhealthy // "N/A")` | Healthy=`\(.value.healthy // "N/A")`"' "$OUTPUT_DIR/comparison.json"
      echo ""
    done
  fi
  
  echo "## Full Comparison Data"
  echo ""
  echo "See \`comparison.json\` for complete structured comparison data."
  echo ""
  echo "## Source Data"
  echo ""
  echo "- **Unhealthy Bundle:** \`$UNHEALTHY_BUNDLE\`"
  echo "- **Healthy Baseline:** \`$HEALTHY_BASELINE\`"
  
} > "$OUTPUT_DIR/comparison_report.md"

# Copy full normalized data for reference
cp "$UNHEALTHY_NORM" "$OUTPUT_DIR/unhealthy_normalized.json"
cp "$HEALTHY_NORM" "$OUTPUT_DIR/healthy_normalized.json"

rm -f "$UNHEALTHY_NORM" "$HEALTHY_NORM"

log "Comparison complete!"
log "Report: $OUTPUT_DIR/comparison_report.md"
log "JSON: $OUTPUT_DIR/comparison.json"
echo ""
cat "$OUTPUT_DIR/comparison_report.md"

