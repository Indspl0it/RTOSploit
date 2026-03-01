# Reporting

RTOSploit generates security reports from fuzzing crashes, exploit results, and CVE correlations. Two formats are supported: SARIF (machine-readable, IDE-compatible) and HTML (human-readable dashboard).

---

## Generating Reports

### From the CLI

```bash
rtosploit report \
  --input-dir ./scan-output \
  --output ./reports \
  --format both \
  --firmware firmware.bin \
  --architecture armv7m
```

### From the Full Scan

The `scan` command generates reports automatically at the end of the pipeline:

```bash
rtosploit scan \
  --firmware firmware.bin \
  --machine mps2-an385 \
  --output ./scan-output \
  --format both
# Produces:
#   scan-output/report.sarif.json
#   scan-output/report.html
```

### From Interactive Mode

Select **Generate Reports** from the firmware menu. Choose formats and output directory.

---

## SARIF Report

SARIF (Static Analysis Results Format) is a JSON schema standardised for communicating static analysis findings to developer tools.

### File: `report.sarif.json`

Top-level structure:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "RTOSploit",
          "rules": [ ... ]
        }
      },
      "results": [ ... ]
    }
  ]
}
```

### Result Entry

Each security finding maps to one SARIF result:

```json
{
  "ruleId": "RTOS001",
  "level": "error",
  "message": {
    "text": "EXPLOITABLE crash: PC redirected to attacker-controlled address 0x41414149"
  },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {
          "uri": "firmware.bin"
        }
      }
    }
  ],
  "properties": {
    "severity": "CRITICAL",
    "exploitability": "EXPLOITABLE",
    "pc": "0x41414149",
    "fault_address": "0x00000008",
    "cfsr_flags": ["INVPC", "DACCVIOL"],
    "minimized_input_size": 64
  }
}
```

### Severity → SARIF Level Mapping

| RTOSploit Severity | SARIF Level |
|-------------------|-------------|
| `CRITICAL` | `error` |
| `HIGH` | `error` |
| `MEDIUM` | `warning` |
| `LOW` | `note` |
| `INFO` | `none` |

### IDE Integration

**VS Code:**
1. Install the "SARIF Viewer" extension (Microsoft)
2. Open `report.sarif.json` in VS Code — findings appear in the Problems panel

**GitHub Code Scanning:**
```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: scan-output/report.sarif.json
```

Findings appear in the repository's Security → Code Scanning Alerts tab.

---

## HTML Report

The HTML dashboard provides an at-a-glance security assessment.

### File: `report.html`

Sections:
1. **Executive Summary** — Finding counts by severity, overall risk rating
2. **Coverage Statistics** — Total/covered instructions, coverage percentage
3. **Findings Table** — All findings sorted by severity with expandable details
4. **CVE Correlation** — Applicable CVEs with CVSS scores and descriptions
5. **Metadata** — Target firmware, architecture, scan timestamp, fuzzing duration

### Finding Details (expanded)

Each finding card shows:
- Classification (EXPLOITABLE / PROBABLY_EXPLOITABLE / UNKNOWN)
- Fault type and address
- Register state at crash time (PC, LR, SP, R0–R3)
- CFSR flags decoded into human-readable descriptions
- Original and minimized input sizes
- Hex dump of the minimized crash input

---

## Data Model

### `Finding` Dataclass

```python
@dataclass
class Finding:
    id: str                      # Unique finding ID (e.g. "crash_003")
    title: str                   # Short description
    severity: str                # CRITICAL | HIGH | MEDIUM | LOW | INFO
    category: str                # "crash" | "exploit" | "cve" | "static"
    description: str             # Full description
    crash_type: str | None       # SEGFAULT | BUSFAULT | etc.
    pc: str | None               # Program counter at fault (hex)
    fault_address: str | None    # Faulting memory address (hex)
    registers: dict | None       # Register snapshot
    exploitability: str | None   # EXPLOITABLE | PROBABLY_EXPLOITABLE | etc.
    cve_id: str | None           # Associated CVE if applicable
    input_size: int | None       # Original crash input size
    minimized_size: int | None   # Minimized input size
    reproducible_input: str | None  # Base64-encoded minimized input
```

### `EngagementReport` Dataclass

```python
@dataclass
class EngagementReport:
    engagement_id: str           # Unique report ID (UUID)
    timestamp: str               # ISO 8601
    firmware_path: str
    rtos_detected: str
    architecture: str
    findings: list[Finding]
    coverage_percent: float | None
    total_instructions: int | None
    covered_instructions: int | None
    fuzz_duration_seconds: int | None
    metadata: dict               # Arbitrary key-value pairs
```

---

## Input Directory Structure

The reporter reads JSON files from `--input-dir`. It auto-classifies files based on their content:

| File pattern | Classified as |
|-------------|--------------|
| `crashes/*.json` | Crash finding |
| `triage/*.json` | Triaged crash (with exploitability) |
| `exploits/*.json` | Exploit result |
| `cves/*.json` | CVE correlation result |

Files that cannot be parsed are skipped with a warning.

---

## Scripting with JSON Reports

```bash
# Count critical findings
rtosploit --json report --input-dir ./scan-output --output /tmp/rpt --format sarif
cat /tmp/rpt/report.sarif.json \
  | jq '[.runs[0].results[] | select(.level == "error")] | length'

# Extract all exploitable crash PCs
jq '.runs[0].results[].properties | select(.exploitability == "EXPLOITABLE") | .pc' \
  /tmp/rpt/report.sarif.json
```
