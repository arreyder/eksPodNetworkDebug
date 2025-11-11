#!/usr/bin/env bash
# Analyze packet capture files (pcap or text format) with pod mapping
# Usage: ./sgfp_analyze_pcap.sh <capture-file> [pod-name] [namespace] [bundle-dir]

set -euo pipefail

CAPTURE_FILE="${1:?usage: sgfp_analyze_pcap.sh <capture-file> [pod-name] [namespace] [bundle-dir]}"
POD="${2:-}"
NS="${3:-default}"
BUNDLE_DIR="${4:-}"

# Helper function to map IP to pod
map_ip_to_pod() {
  local ip="$1"
  [ -z "$ip" ] && return
  [ "$ip" = "0.0.0.0" ] && return
  
  if [ -n "$POD_IP_MAP" ] && [ -f "$POD_IP_MAP" ]; then
    local pod_info=$(grep -m1 "^$ip " "$POD_IP_MAP" 2>/dev/null | awk '{print $2, $3}' || echo "")
    if [ -n "$pod_info" ]; then
      echo " -> $pod_info"
    fi
  fi
}

if [ ! -f "$CAPTURE_FILE" ]; then
  echo "[ERROR] Capture file not found: $CAPTURE_FILE"
  exit 1
fi

OUTPUT_DIR="pcap_analysis_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo "[PCAP] Analyzing packet capture: $CAPTURE_FILE"
echo "[PCAP] Output directory: $OUTPUT_DIR"

# Try to find pod IP map from bundle directory
POD_IP_MAP=""
if [ -n "$BUNDLE_DIR" ] && [ -d "$BUNDLE_DIR" ]; then
  POD_IP_MAP=$(find "$BUNDLE_DIR" -name "node_pod_ip_map.txt" -type f 2>/dev/null | head -1 || echo "")
elif [ -n "$POD" ]; then
  # Try to find bundle automatically
  BUNDLE_DIR=$(find data -type d -name "*bundle*${POD}*" -o -name "*bundle*${NS}*${POD}*" 2>/dev/null | sort -r | head -1 || echo "")
  if [ -n "$BUNDLE_DIR" ]; then
    POD_IP_MAP=$(find "$BUNDLE_DIR" -name "node_pod_ip_map.txt" -type f 2>/dev/null | head -1 || echo "")
  fi
fi

if [ -n "$POD_IP_MAP" ] && [ -f "$POD_IP_MAP" ]; then
  echo "[PCAP] Using pod IP map: $POD_IP_MAP"
  POD_MAP_COUNT=$(wc -l < "$POD_IP_MAP" 2>/dev/null | tr -d '[:space:]' || echo "0")
  echo "[PCAP] Found $POD_MAP_COUNT pod IP mappings"
else
  echo "[PCAP] No pod IP map found - IPs will not be mapped to pods"
fi

# Detect file type
FILE_TYPE=$(file "$CAPTURE_FILE" 2>/dev/null | grep -oE "(text|pcap|tcpdump)" || echo "unknown")

if [[ "$FILE_TYPE" == *"pcap"* ]] || [[ "$CAPTURE_FILE" == *.pcap ]]; then
  echo "[PCAP] Detected pcap file - converting to text format..."
  # Convert pcap to text if tcpdump/tshark available
  if command -v tcpdump >/dev/null 2>&1; then
    tcpdump -r "$CAPTURE_FILE" -n -v > "$OUTPUT_DIR/capture_text.txt" 2>&1 || {
      echo "[WARN] tcpdump conversion failed, trying tshark..."
      if command -v tshark >/dev/null 2>&1; then
        tshark -r "$CAPTURE_FILE" -V > "$OUTPUT_DIR/capture_text.txt" 2>&1 || {
          echo "[ERROR] Failed to convert pcap file"
          exit 1
        }
      else
        echo "[ERROR] Need tcpdump or tshark to convert pcap file"
        exit 1
      fi
    }
    CAPTURE_TEXT="$OUTPUT_DIR/capture_text.txt"
  elif command -v tshark >/dev/null 2>&1; then
    tshark -r "$CAPTURE_FILE" -V > "$OUTPUT_DIR/capture_text.txt" 2>&1 || {
      echo "[ERROR] Failed to convert pcap file"
      exit 1
    }
    CAPTURE_TEXT="$OUTPUT_DIR/capture_text.txt"
  else
    echo "[ERROR] Need tcpdump or tshark to convert pcap file"
    exit 1
  fi
else
  echo "[PCAP] Detected text file - using directly"
  CAPTURE_TEXT="$CAPTURE_FILE"
fi

echo "[PCAP] Analyzing capture file..."

# 1. Connection summary
echo "[PCAP] [1/10] Connection summary..."
{
  echo "=== TCP Connections ==="
  grep -E "Flags \[|SYN|ACK|FIN|RST" "$CAPTURE_TEXT" 2>/dev/null | head -100 || echo "No TCP flags found"
  echo ""
  echo "=== Connection States ==="
  grep -oE "(SYN|ACK|FIN|RST|ESTABLISHED|TIME_WAIT|CLOSE)" "$CAPTURE_TEXT" 2>/dev/null | sort | uniq -c | sort -rn || echo "No connection states found"
} > "$OUTPUT_DIR/01_connection_summary.txt"

# 2. Failed connections
echo "[PCAP] [2/10] Failed connections..."
{
  echo "=== RST (Reset) Packets ==="
  grep -i "RST\|reset" "$CAPTURE_TEXT" 2>/dev/null | head -50 || echo "No RST packets found"
  echo ""
  echo "=== Connection Refused ==="
  grep -i "refused\|connection refused" "$CAPTURE_TEXT" 2>/dev/null | head -50 || echo "No connection refused found"
  echo ""
  echo "=== Timeouts ==="
  grep -i "timeout\|timed out" "$CAPTURE_TEXT" 2>/dev/null | head -50 || echo "No timeouts found"
} > "$OUTPUT_DIR/02_failed_connections.txt"

# 3. TLS/SSL handshake analysis
echo "[PCAP] [3/10] TLS/SSL handshake analysis..."
{
  echo "=== TLS Handshakes ==="
  grep -iE "TLS|SSL|handshake|Client Hello|Server Hello" "$CAPTURE_TEXT" 2>/dev/null | head -100 || echo "No TLS handshakes found"
  echo ""
  echo "=== TLS Errors ==="
  grep -iE "TLS.*error|SSL.*error|certificate.*error|handshake.*fail" "$CAPTURE_TEXT" 2>/dev/null | head -50 || echo "No TLS errors found"
} > "$OUTPUT_DIR/03_tls_analysis.txt"

# 4. DNS queries
echo "[PCAP] [4/10] DNS queries..."
{
  echo "=== DNS Queries ==="
  grep -iE "DNS|query|A\?|AAAA\?" "$CAPTURE_TEXT" 2>/dev/null | head -100 || echo "No DNS queries found"
  echo ""
  echo "=== DNS Responses ==="
  grep -iE "DNS.*response|DNS.*answer" "$CAPTURE_TEXT" 2>/dev/null | head -50 || echo "No DNS responses found"
} > "$OUTPUT_DIR/04_dns_queries.txt"

# 5. Retransmissions
echo "[PCAP] [5/10] Retransmissions..."
{
  echo "=== Retransmissions ==="
  grep -iE "retrans|retransmit|duplicate" "$CAPTURE_TEXT" 2>/dev/null | head -50 || echo "No retransmissions found"
} > "$OUTPUT_DIR/05_retransmissions.txt"

# 6. Port analysis
echo "[PCAP] [6/10] Port analysis..."
{
  echo "=== Most Active Ports ==="
  grep -oE ":[0-9]+" "$CAPTURE_TEXT" 2>/dev/null | sed 's/://' | sort | uniq -c | sort -rn | head -20 || echo "No port information found"
  echo ""
  echo "=== Connection Attempts by Port ==="
  grep -E "SYN|connect" "$CAPTURE_TEXT" 2>/dev/null | grep -oE ":[0-9]+" | sed 's/://' | sort | uniq -c | sort -rn | head -20 || echo "No connection attempts found"
} > "$OUTPUT_DIR/06_port_analysis.txt"

# 7. IP addresses (with pod mapping)
echo "[PCAP] [7/10] IP address analysis..."
{
  echo "=== Source IPs (with pod mapping) ==="
  grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" "$CAPTURE_TEXT" 2>/dev/null | sort | uniq -c | sort -rn | head -20 | \
    while read -r count ip; do
      [ -z "$ip" ] && continue
      pod_info=$(map_ip_to_pod "$ip")
      echo "  $count $ip$pod_info"
    done || echo "No IPs found"
  echo ""
  echo "=== Destination IPs (with pod mapping) ==="
  grep -E ">|->" "$CAPTURE_TEXT" 2>/dev/null | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | sort | uniq -c | sort -rn | head -20 | \
    while read -r count ip; do
      [ -z "$ip" ] && continue
      pod_info=$(map_ip_to_pod "$ip")
      echo "  $count $ip$pod_info"
    done || echo "No destination IPs found"
} > "$OUTPUT_DIR/07_ip_analysis.txt"

# 8. Errors and warnings
echo "[PCAP] [8/10] Errors and warnings..."
{
  echo "=== All Errors ==="
  grep -iE "error|fail|denied|blocked|drop" "$CAPTURE_TEXT" 2>/dev/null | head -100 || echo "No errors found"
  echo ""
  echo "=== Warnings ==="
  grep -iE "warn|alert" "$CAPTURE_TEXT" 2>/dev/null | head -50 || echo "No warnings found"
} > "$OUTPUT_DIR/08_errors_warnings.txt"

# 9. Connection patterns (if pod info available)
if [ -n "$POD" ] || [ -n "$BUNDLE_DIR" ]; then
  echo "[PCAP] [9/10] Pod-specific analysis..."
  if [ -z "$BUNDLE_DIR" ] && [ -n "$POD" ]; then
    BUNDLE_DIR=$(find data -type d -name "*bundle*${POD}*" -o -name "*bundle*${NS}*${POD}*" 2>/dev/null | sort -r | head -1 || echo "")
  fi
  
  if [ -n "$BUNDLE_DIR" ]; then
    POD_IP_FILE=$(find "$BUNDLE_DIR" -name "pod_ip.txt" -type f 2>/dev/null | head -1 || echo "")
    if [ -n "$POD_IP_FILE" ]; then
      POD_IP=$(grep "^POD_IP=" "$POD_IP_FILE" 2>/dev/null | cut -d= -f2- || echo "")
      if [ -n "$POD_IP" ]; then
        echo "[PCAP] Found pod IP from diagnostics: $POD_IP"
        {
          echo "=== Traffic TO pod ($POD_IP) ==="
          grep "$POD_IP" "$CAPTURE_TEXT" 2>/dev/null | \
            grep -oE "Src: ([0-9]{1,3}\.){3}[0-9]{1,3}" | \
            sed 's/Src: //' | sort | uniq -c | sort -rn | head -20 | \
            while read -r count src_ip; do
              pod_info=$(map_ip_to_pod "$src_ip")
              echo "  $count packets from $src_ip$pod_info"
            done || echo "No inbound traffic found"
          echo ""
          echo "=== Traffic FROM pod ($POD_IP) ==="
          grep "$POD_IP" "$CAPTURE_TEXT" 2>/dev/null | \
            grep -oE "Dst: ([0-9]{1,3}\.){3}[0-9]{1,3}" | \
            sed 's/Dst: //' | sort | uniq -c | sort -rn | head -20 | \
            while read -r count dst_ip; do
              pod_info=$(map_ip_to_pod "$dst_ip")
              echo "  $count packets to $dst_ip$pod_info"
            done || echo "No outbound traffic found"
        } > "$OUTPUT_DIR/09_pod_specific.txt"
      fi
    fi
  fi
fi

# 10. Summary statistics
echo "[PCAP] [10/10] Summary statistics..."
{
  echo "=== File Statistics ==="
  echo "Total lines: $(wc -l < "$CAPTURE_TEXT" 2>/dev/null || echo "0")"
  echo "File size: $(du -h "$CAPTURE_TEXT" 2>/dev/null | awk '{print $1}' || echo "unknown")"
  echo ""
  echo "=== Packet Counts ==="
  echo "TCP packets: $(grep -ci "tcp" "$CAPTURE_TEXT" 2>/dev/null || echo "0")"
  echo "UDP packets: $(grep -ci "udp" "$CAPTURE_TEXT" 2>/dev/null || echo "0")"
  echo "SYN packets: $(grep -ci "SYN" "$CAPTURE_TEXT" 2>/dev/null || echo "0")"
  echo "RST packets: $(grep -ci "RST\|reset" "$CAPTURE_TEXT" 2>/dev/null || echo "0")"
  echo "FIN packets: $(grep -ci "FIN" "$CAPTURE_TEXT" 2>/dev/null || echo "0")"
  echo ""
  echo "=== Error Counts ==="
  echo "Errors: $(grep -ci "error" "$CAPTURE_TEXT" 2>/dev/null || echo "0")"
  echo "Failures: $(grep -ci "fail" "$CAPTURE_TEXT" 2>/dev/null || echo "0")"
  echo "Timeouts: $(grep -ci "timeout" "$CAPTURE_TEXT" 2>/dev/null || echo "0")"
  echo "Refused: $(grep -ci "refused" "$CAPTURE_TEXT" 2>/dev/null || echo "0")"
} > "$OUTPUT_DIR/10_summary.txt"

echo ""
echo "[PCAP] Analysis complete!"
echo "[PCAP] Results saved to: $OUTPUT_DIR"
echo "[PCAP] Key files:"
echo "  - 02_failed_connections.txt (connection failures)"
echo "  - 03_tls_analysis.txt (TLS handshake issues)"
echo "  - 05_retransmissions.txt (packet retransmissions)"
echo "  - 08_errors_warnings.txt (all errors)"
echo "  - 10_summary.txt (overall statistics)"

