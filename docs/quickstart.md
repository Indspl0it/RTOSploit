# Quickstart Guide

Get up and running with RTOSploit in five minutes. This guide assumes you have completed [installation](installation.md).

---

## Interactive Mode

The fastest way to explore RTOSploit is the interactive menu:

```bash
rtosploit
```

Use arrow keys to navigate, Enter to select. The menu adapts based on whether firmware is loaded.

### Step 1 — Load Firmware

Select **Load Firmware** and type a path (tab-completion works):

```
? Firmware file path: /path/to/firmware.bin
```

RTOSploit will:
1. Detect the binary format (ELF, Intel HEX, SREC, or raw)
2. Fingerprint the RTOS and architecture
3. Select a default QEMU machine based on the detected architecture
4. Display a summary panel:

```
┌──────────────────────────────────────────┐
│ Firmware:  firmware.bin (245 KB)         │
│ RTOS:      FreeRTOS 10.4.3               │
│ Arch:      armv7m                        │
│ Machine:   mps2-an385 (auto)             │
│ Confidence: 92%                          │
└──────────────────────────────────────────┘
```

### Step 2 — Run Static Analysis

From the firmware menu, select **Static Analysis**. Choose which analyses to run:

```
? Select analyses to run:
  [x] RTOS Fingerprint
  [x] Heap Allocator Detection
  [x] MPU Configuration Check
  [ ] String Extraction
```

Results are displayed inline with Rich tables.

### Step 3 — Fuzz Firmware

Select **Fuzz Firmware**. Answer the prompts:

```
? Fuzz timeout (seconds, 0=unlimited): 60
? Seed corpus directory (optional):
? Output directory: ./fuzz-output
```

The live dashboard runs for 60 seconds:

```
┌──────────── RTOSploit Fuzzer Dashboard ─────────────┐
│ Elapsed Time    00:00:47                             │
│ Executions      7,203                               │
│ Exec/sec        153.3                               │
│ Crashes Found   1                                   │
│ Coverage %       4.1%                               │
│ Corpus Size      8                                  │
└─────────────────────────────────────────────────────┘
```

If crashes are found, you'll be offered to triage or report immediately.

### Step 4 — Triage Crashes

Select **Triage Crash Directory** from the firmware menu. Provide the crash directory:

```
? Crash directory: ./fuzz-output/crashes
? Minimize crash inputs? Yes
```

RTOSploit replays each crash, classifies exploitability, and minimizes inputs.

### Step 5 — Generate Reports

Select **Generate Reports**. Choose formats and output directory:

```
? Report format(s): [x] SARIF  [x] HTML
? Output directory: ./results
```

Open `results/report.html` in a browser for the interactive dashboard.

---

## CLI Mode

Every action in interactive mode has a CLI equivalent for scripting and CI.

### Quick RTOS Fingerprint

```bash
rtosploit analyze --firmware firmware.bin --detect-rtos
```

### Five-Minute Fuzz

```bash
rtosploit fuzz \
  --firmware firmware.bin \
  --machine mps2-an385 \
  --output ./fuzz-out \
  --timeout 300
```

### Full Scan (All Phases)

```bash
rtosploit scan \
  --firmware firmware.bin \
  --machine mps2-an385 \
  --fuzz-timeout 120 \
  --output ./scan-output \
  --fail-on high
echo "Exit code: $?"
```

### CVE Check

```bash
rtosploit cve scan --firmware firmware.bin
```

### Use the Exploit Console

```bash
rtosploit console
```

```
rtosploit> search freertos
rtosploit> use freertos/heap_overflow
rtosploit(freertos/heap_overflow)> show options
rtosploit(freertos/heap_overflow)> set firmware ./firmware.bin
rtosploit(freertos/heap_overflow)> set machine mps2-an385
rtosploit(freertos/heap_overflow)> check
rtosploit(freertos/heap_overflow)> exploit
```

---

## JSON Output for Scripting

Any command can output machine-readable JSON with the global `--json` flag:

```bash
# Get RTOS type as JSON
rtosploit --json analyze --firmware fw.bin --detect-rtos | jq '.rtos.detected'
# "freertos"

# List all CVEs as JSON array
rtosploit --json cve scan --firmware fw.bin | jq '.[].cve_id'

# Get coverage percentage
rtosploit --json coverage stats --firmware fw.bin --bitmap ./bitmap \
  | jq '.coverage_percent'
```

---

## Next Steps

- [CLI Reference](../README.md#cli-reference) — Full option documentation for every command
- [Architecture](architecture.md) — System design, data flows, and Mermaid diagrams
- [Writing Scanner Modules](writing-scanners.md) — Add your own vulnerability scanner modules
- [CI/CD Integration](ci-integration.md) — GitHub Actions, GitLab CI, and Makefile recipes
- [Crash Triage](crash-triage.md) — Deep dive into exploitability classification
- [CVE Correlation](cve-correlation.md) — Database internals and NVD sync
- [Coverage Visualization](coverage.md) — Bitmap format, mapping, and HTML reports
- [Reporting](reporting.md) — SARIF structure and HTML dashboard details
