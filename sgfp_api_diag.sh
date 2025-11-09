#!/usr/bin/env bash
set -euo pipefail

POD="${1:-}"
NS="${2:-default}"
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
START="$(date -u -d "${WINDOW_MINUTES} minutes ago" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -v-"${WINDOW_MINUTES}"M +"%Y-%m-%dT%H:%M:%SZ")"

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

jq -s 'add' "$OUT/attach_raw.json" "$OUT/create_raw.json" "$OUT/delete_raw.json" > "$OUT/events_eni.json" || echo '[]' > "$OUT/events_eni.json"

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

# Throttles/errors (TSV) + summaries
jq -r '
  .[]?
  | select( (.ErrorCode // "") != "" or ((.ErrorMessage // "") | test("(?i)throttl|rate.?exceeded|limit")) )
  | [ .EventTime, .EventName, (.User // "unknown"), (.IP // "unknown"), (.ErrorCode // ""), (.ErrorMessage // "") ]
  | @tsv
' "$OUT/flat_events.json" > "$OUT/eni_errors.tsv" || : > "$OUT/eni_errors.tsv"

jq -r '
  .[]? | select( (.ErrorCode // "") != "" or ((.ErrorMessage // "") | test("(?i)throttl|rate.?exceeded|limit")) ) | .EventName
' "$OUT/flat_events.json" | sort | uniq -c | sort -nr > "$OUT/throttle_by_action.txt" || : > "$OUT/throttle_by_action.txt"

jq -r '
  .[]? | select( (.ErrorCode // "") != "" or ((.ErrorMessage // "") | test("(?i)throttl|rate.?exceeded|limit")) ) | .User
' "$OUT/flat_events.json" | sort | uniq -c | sort -nr > "$OUT/throttle_by_caller.txt" || : > "$OUT/throttle_by_caller.txt"

jq -r '.[].EventName // empty' "$OUT/flat_events.json" | sort | uniq -c | sort -nr > "$OUT/top_api_calls.txt" || : > "$OUT/top_api_calls.txt"

# Summary
TOT_EVENTS="$(jq -r 'length' "$OUT/events_eni.json" 2>/dev/null || echo 0)"
TOT_FLAT="$(jq -r 'length' "$OUT/flat_events.json" 2>/dev/null || echo 0)"
TOT_ERRS="$(wc -l < "$OUT/eni_errors.tsv" 2>/dev/null | tr -d '[:space:]' || echo 0)"
log "Done"
log "Events found: $TOT_EVENTS  | flattened: $TOT_FLAT  | throttles/errors: $TOT_ERRS"
log "Output dir: $OUT"
