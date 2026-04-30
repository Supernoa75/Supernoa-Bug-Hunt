# Automated Bug Hunting Script

This repository now includes `auto_bug_hunt.sh`, a one-command orchestrator for common bug-hunting workflows.

## What it does

It attempts to run these tools (when installed):
- `subfinder`
- `assetfinder`
- `httpx`
- `naabu`
- `nuclei`
- `ffuf`
- `whatweb`
- `nikto`

If a tool is not installed, it is skipped gracefully and logged.

## Usage

```bash
./auto_bug_hunt.sh -t https://example.com -o output
```

Options:
- `-t` target URL or host (required)
- `-o` output directory (default: `bughunt_output`)
- `-w` wordlist for `ffuf` (default: `/usr/share/wordlists/dirb/common.txt`)
- `-T` thread count (default: `30`)

## Output

The script creates:
- `recon/` (subdomains, live hosts)
- `scan/` (ports, nuclei findings)
- `web/` (content fuzzing, web fingerprinting)
- `report.md` (summary report)

## Important

Use this only on targets where you have explicit authorization to test.
Always manually verify results before submitting vulnerability reports.
