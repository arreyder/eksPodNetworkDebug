#!/usr/bin/env bash
set -euo pipefail

WINDOW_MINUTES="${WINDOW_MINUTES:-2880}"   # default 2 days

OUT="sgfp_api_diag_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"

log()  { printf "[API] %s\n" "$*"; }
warn() { printf "[API] WARN: %s\n" "$*" >&2; }
err()  { printf "[API] ERROR: %s\n" "$*" >&2; }

for cmd in aws jq date; do command -v "$cmd" >/dev/null || { err "Missing dependency: $cmd"; exit 1; }; done

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
if [ -z "$REGION" ]; then REGION="$(aws configure get region 2>/dev/null || true)"; fi
if [ -z "$REGION" ]; then err "No AWS region. Set AWS_REGION (e.g., us-west-2)."; exit 1; fi

END="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
# Try GNU date first, fall back to BSD date
if date -u -d "${WINDOW_MINUTES} minutes ago" +"%Y-%m-%dT%H:%M:%SZ" >/dev/null 2>&1; then
  START="$(date -u -d "${WINDOW_MINUTES} minutes ago" +"%Y-%m-%dT%H:%M:%SZ")"
elif date -u -v-"${WINDOW_MINUTES}"M +"%Y-%m-%dT%H:%M:%SZ" >/dev/null 2>&1; then
  START="$(date -u -v-"${WINDOW_MINUTES}"M +"%Y-%m-%dT%H:%M:%SZ")"
else
  # Fallback: calculate seconds and use epoch
  SECONDS_AGO=$((WINDOW_MINUTES * 60))
  START_EPOCH=$(($(date -u +%s) - SECONDS_AGO))
  START="$(date -u -d "@${START_EPOCH}" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -r "${START_EPOCH}" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "")"
  if [ -z "$START" ]; then
    err "Failed to calculate start time. Please ensure date command supports -d or -v flag."
    exit 1
  fi
fi

log "Collecting CloudTrail ENI calls for last ${WINDOW_MINUTES} minutes"
log "Region: $REGION"
log "Output: $OUT"

aws sts get-caller-identity --region "$REGION" >/dev/null 2>&1 || { err "AWS creds/region invalid"; exit 1; }

lookup_all() {
  local name="$1" out="$2" tmp token
  tmp="$OUT/_tmp_${name}.json"
  echo '[]' > "$out"
  if ! aws cloudtrail lookup-events --region "$REGION" \
        --lookup-attributes AttributeKey=EventName,AttributeValue="$name" \
        --start-time "$START" --end-time "$END" --max-results 50 > "$tmp" 2>"$tmp.err"; then
    warn "lookup-events($name) failed: $(tr -d '\n' < "$tmp.err" | cut -c1-200)"; echo '{"Events":[]}' > "$tmp"
  fi
  jq -s '.[0] + [ .[1].Events[]? ]' "$out" "$tmp" > "$out.tmp" && mv "$out.tmp" "$out"
  token="$(jq -r '.NextToken // empty' "$tmp" 2>/dev/null || true)"
  while [ -n "$token" ] && [ "$token" != "null" ]; do
    if ! aws cloudtrail lookup-events --region "$REGION" \
          --lookup-attributes AttributeKey=EventName,AttributeValue="$name" \
          --start-time "$START" --end-time "$END" --max-results 50 --next-token "$token" > "$tmp" 2>"$tmp.err"; then
      warn "lookup-events($name,next) failed: $(tr -d '\n' < "$tmp.err" | cut -c1-200)"; break
    fi
    jq -s '.[0] + [ .[1].Events[]? ]' "$out" "$tmp" > "$out.tmp" && mv "$out.tmp" "$out"
    token="$(jq -r '.NextToken // empty' "$tmp" 2>/dev/null || true)"
  done
  rm -f "$tmp" "$tmp.err" 2>/dev/null || true
}

log "Querying CloudTrail (paginated)..."
lookup_all "AttachNetworkInterface"  "$OUT/attach_raw.json"
lookup_all "CreateNetworkInterface"  "$OUT/create_raw.json"
lookup_all "DeleteNetworkInterface"  "$OUT/delete_raw.json"

# Merge arrays, handling empty files gracefully
jq -s 'add | if . == null then [] else . end' "$OUT/attach_raw.json" "$OUT/create_raw.json" "$OUT/delete_raw.json" > "$OUT/events_eni.json" 2>/dev/null || echo '[]' > "$OUT/events_eni.json"

# Flatten to array
jq '
  map(
    . as $e
    | ( $e.CloudTrailEvent | fromjson? // {} ) as $c
    | {
        EventTime:   ($e.EventTime   // ($c.eventTime   // "")),
        EventName:   ($e.EventName   // ($c.eventName   // "")),
        EventSource: ($e.EventSource // ($c.eventSource // "")),
        User:        ($c.userIdentity.arn // "unknown"),
        IP:          ($c.sourceIPAddress  // "unknown"),
        ErrorCode:   ($c.errorCode        // ""),
        ErrorMessage:($c.errorMessage     // "")
      }
  )
' "$OUT/events_eni.json" > "$OUT/flat_events.json" || echo '[]' > "$OUT/flat_events.json"

# Categorize all events with error codes/messages
# Real errors/throttles (exclude dry runs as they're successful validations)
jq -r '
  .[]?
  | select( 
      ((.ErrorCode // "") != "" and (.ErrorCode // "") != "Client.DryRunOperation") or 
      ((.ErrorMessage // "") | test("(?i)throttl|rate.?exceeded|limit")) 
    )
  | [ .EventTime, .EventName, (.User // "unknown"), (.IP // "unknown"), (.ErrorCode // ""), (.ErrorMessage // "") ]
  | @tsv
' "$OUT/flat_events.json" > "$OUT/eni_errors.tsv" || : > "$OUT/eni_errors.tsv"

# Dry runs (informational - successful validations, not errors)
jq -r '
  .[]?
  | select((.ErrorCode // "") == "Client.DryRunOperation")
  | [ .EventTime, .EventName, (.User // "unknown"), (.IP // "unknown"), (.ErrorCode // ""), (.ErrorMessage // "") ]
  | @tsv
' "$OUT/flat_events.json" > "$OUT/eni_dryruns.tsv" || : > "$OUT/eni_dryruns.tsv"

# All events with any error code/message (including dry runs) - for comprehensive view
jq -r '
  .[]?
  | select((.ErrorCode // "") != "")
  | [ .EventTime, .EventName, (.User // "unknown"), (.IP // "unknown"), (.ErrorCode // ""), (.ErrorMessage // "") ]
  | @tsv
' "$OUT/flat_events.json" > "$OUT/eni_all_issues.tsv" || : > "$OUT/eni_all_issues.tsv"

# Summaries for real errors/throttles
jq -r '
  .[]? | select( 
    ((.ErrorCode // "") != "" and (.ErrorCode // "") != "Client.DryRunOperation") or 
    ((.ErrorMessage // "") | test("(?i)throttl|rate.?exceeded|limit")) 
  ) | .EventName
' "$OUT/flat_events.json" | sort | uniq -c | sort -nr > "$OUT/throttle_by_action.txt" || : > "$OUT/throttle_by_action.txt"

jq -r '
  .[]? | select( 
    ((.ErrorCode // "") != "" and (.ErrorCode // "") != "Client.DryRunOperation") or 
    ((.ErrorMessage // "") | test("(?i)throttl|rate.?exceeded|limit")) 
  ) | .User
' "$OUT/flat_events.json" | sort | uniq -c | sort -nr > "$OUT/throttle_by_caller.txt" || : > "$OUT/throttle_by_caller.txt"

# Summary by error code type
jq -r '
  .[]? | select((.ErrorCode // "") != "") | .ErrorCode
' "$OUT/flat_events.json" | sort | uniq -c | sort -nr > "$OUT/error_codes_summary.txt" || : > "$OUT/error_codes_summary.txt"

jq -r '.[].EventName // empty' "$OUT/flat_events.json" | sort | uniq -c | sort -nr > "$OUT/top_api_calls.txt" || : > "$OUT/top_api_calls.txt"

# Summary by user/caller (all events, not just errors)
jq -r '.[]? | .User // "unknown"' "$OUT/flat_events.json" | sort | uniq -c | sort -nr > "$OUT/calls_by_user.txt" || : > "$OUT/calls_by_user.txt"

# Summary
TOT_EVENTS="$(jq -r 'length' "$OUT/events_eni.json" 2>/dev/null || echo 0)"
TOT_FLAT="$(jq -r 'length' "$OUT/flat_events.json" 2>/dev/null || echo 0)"
TOT_ERRS="$(wc -l < "$OUT/eni_errors.tsv" 2>/dev/null | tr -d '[:space:]' || echo 0)"
TOT_DRYRUNS="$(wc -l < "$OUT/eni_dryruns.tsv" 2>/dev/null | tr -d '[:space:]' || echo 0)"
TOT_ALL_ISSUES="$(wc -l < "$OUT/eni_all_issues.tsv" 2>/dev/null | tr -d '[:space:]' || echo 0)"
log "Done"
log "Events found: $TOT_EVENTS  | flattened: $TOT_FLAT"
log "Real errors/throttles: $TOT_ERRS  | Dry runs: $TOT_DRYRUNS  | All issues: $TOT_ALL_ISSUES"
log "Output dir: $OUT"
