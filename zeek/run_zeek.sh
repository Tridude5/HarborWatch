#!/bin/bash
set -euo pipefail

PCAP="/pcaps/sample.pcap"
OUTDIR="/logs"

if [ ! -f "$PCAP" ]; then
  echo "ERROR: Missing $PCAP"
  echo "Put a PCAP at ./pcaps/sample.pcap"
  exit 1
fi

mkdir -p "$OUTDIR"

echo "[zeek] Processing PCAP: $PCAP"
cd "$OUTDIR"

# -C: disable checksum validation (common for captured traffic)
# LogAscii::use_json=T: output JSON
zeek -C -r "$PCAP" LogAscii::use_json=T

echo "[zeek] Done. Logs written to $OUTDIR"
# Keep container alive briefly so Vector can read files in some environments.
sleep 5
