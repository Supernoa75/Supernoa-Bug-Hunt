#!/usr/bin/env bash
set -euo pipefail

# Automated bug hunting orchestrator
# Usage:
#   ./auto_bug_hunt.sh -t https://target.com -o results
#
# This script runs multiple recon and vulnerability scanning tools if installed.

TARGET=""
OUTDIR="bughunt_output"
THREADS=30
WORDLIST="/usr/share/wordlists/dirb/common.txt"

usage() {
  cat <<USAGE
Usage: $0 -t <target_url_or_host> [-o output_dir] [-w wordlist] [-T threads]

Examples:
  $0 -t https://example.com
  $0 -t example.com -o output -w /path/to/wordlist.txt -T 50
USAGE
}

while getopts ":t:o:w:T:h" opt; do
  case "$opt" in
    t) TARGET="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    w) WORDLIST="$OPTARG" ;;
    T) THREADS="$OPTARG" ;;
    h) usage; exit 0 ;;
    :) echo "Missing argument for -$OPTARG"; usage; exit 1 ;;
    \?) echo "Invalid option: -$OPTARG"; usage; exit 1 ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "Error: target is required."
  usage
  exit 1
fi

mkdir -p "$OUTDIR"/{recon,scan,web,logs}

log() {
  printf "[%s] %s\n" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$*"
}

run_if_exists() {
  local tool="$1"; shift
  local logfile="$1"; shift

  if command -v "$tool" >/dev/null 2>&1; then
    log "Running $tool..."
    {
      echo "# Command: $tool $*"
      "$tool" "$@"
    } >"$logfile" 2>&1 || true
  else
    log "Skipping $tool (not installed)."
    echo "$tool not installed" >"$logfile"
  fi
}

# Normalize host/domain for DNS-based tools
HOST=$(echo "$TARGET" | sed -E 's#^https?://##' | cut -d/ -f1 | cut -d: -f1)

log "Target: $TARGET"
log "Output directory: $OUTDIR"

# 1) Subdomain discovery
run_if_exists subfinder "$OUTDIR/recon/subfinder.txt" -d "$HOST" -silent
run_if_exists assetfinder "$OUTDIR/recon/assetfinder.txt" --subs-only "$HOST"

cat "$OUTDIR/recon"/*.txt 2>/dev/null | sort -u > "$OUTDIR/recon/all_hosts.txt" || true
if [[ ! -s "$OUTDIR/recon/all_hosts.txt" ]]; then
  echo "$HOST" > "$OUTDIR/recon/all_hosts.txt"
fi

# 2) Liveness check
run_if_exists httpx "$OUTDIR/recon/alive_hosts.txt" -l "$OUTDIR/recon/all_hosts.txt" -silent -threads "$THREADS"
if [[ ! -s "$OUTDIR/recon/alive_hosts.txt" ]]; then
  cp "$OUTDIR/recon/all_hosts.txt" "$OUTDIR/recon/alive_hosts.txt"
fi

# 3) Port scan
run_if_exists naabu "$OUTDIR/scan/naabu.txt" -list "$OUTDIR/recon/all_hosts.txt" -silent

# 4) Template-based vulnerability scan
run_if_exists nuclei "$OUTDIR/scan/nuclei.txt" -l "$OUTDIR/recon/alive_hosts.txt" -severity low,medium,high,critical -silent

# 5) Directory fuzzing (single URL target)
if [[ "$TARGET" =~ ^https?:// ]]; then
  run_if_exists ffuf "$OUTDIR/web/ffuf.txt" -u "$TARGET/FUZZ" -w "$WORDLIST" -mc all -fc 404 -t "$THREADS"
else
  log "Skipping ffuf because target is not an http(s) URL"
fi

# 6) Basic web tech fingerprint
run_if_exists whatweb "$OUTDIR/web/whatweb.txt" "$TARGET"

# 7) Optional Nikto check
if [[ "$TARGET" =~ ^https?:// ]]; then
  run_if_exists nikto "$OUTDIR/web/nikto.txt" -h "$TARGET"
fi

# 8) Build markdown report
REPORT="$OUTDIR/report.md"
{
  echo "# Automated Bug Hunting Report"
  echo
  echo "- Target: $TARGET"
  echo "- Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
  echo
  echo "## Tool Summary"
  for f in "$OUTDIR"/recon/*.txt "$OUTDIR"/scan/*.txt "$OUTDIR"/web/*.txt; do
    [[ -e "$f" ]] || continue
    name=$(basename "$f")
    lines=$(wc -l < "$f" || echo 0)
    echo "- $name: $lines lines"
  done
  echo
  echo "## Quick Hits (nuclei)"
  if [[ -s "$OUTDIR/scan/nuclei.txt" ]]; then
    head -n 50 "$OUTDIR/scan/nuclei.txt"
  else
    echo "No nuclei findings or nuclei unavailable."
  fi
  echo
  echo "## Next Steps"
  echo "1. Manually validate all findings before reporting."
  echo "2. Prioritize critical/high impact issues first."
  echo "3. Collect proof-of-concept safely and within program scope."
} > "$REPORT"

log "Done. Report: $REPORT"
