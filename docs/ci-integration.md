# CI/CD Integration

RTOSploit's `scan` command is designed as a drop-in CI step that runs all security phases and returns a meaningful exit code.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All findings are below the `--fail-on` severity threshold. Pipeline passes. |
| `1` | One or more findings at or above the threshold. Pipeline fails. |
| `2` | Internal error — QEMU not found, firmware missing, etc. |

---

## `--fail-on` Severity Threshold

Control which severity level triggers a non-zero exit:

| Value | Fails on |
|-------|---------|
| `critical` | Critical findings only (default) |
| `high` | High and above |
| `medium` | Medium and above |
| `low` | Any non-informational finding |
| `any` | Any finding regardless of severity |

---

## GitHub Actions

### Basic Scan

```yaml
name: Firmware Security Scan
on:
  push:
    branches: [main, develop]
  pull_request:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install QEMU
        run: sudo apt-get install -y qemu-system-arm

      - name: Install RTOSploit
        run: pip install -e .

      - name: Run security scan
        run: |
          rtosploit scan \
            --firmware firmware.bin \
            --machine mps2-an385 \
            --fuzz-timeout 120 \
            --format sarif \
            --output scan-output \
            --fail-on high

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: scan-output/report.sarif.json
        if: always()   # Upload even if scan fails

      - name: Upload full scan artifacts
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: scan-output/
        if: always()
```

### Scan with Native Fuzzer

```yaml
      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Build native fuzzer
        run: cargo build --release -p rtosploit-fuzzer

      - name: Run scan with real fuzzing
        run: |
          rtosploit scan \
            --firmware firmware.bin \
            --machine mps2-an385 \
            --fuzz-timeout 300 \
            --output scan-output
```

### Analysis-Only (No Fuzzing)

For fast feedback on every commit — static analysis and CVE check only:

```yaml
      - name: Static analysis and CVE check
        run: |
          rtosploit scan \
            --firmware firmware.bin \
            --machine mps2-an385 \
            --skip-fuzz \
            --format sarif \
            --output scan-output
```

### Scheduled Deep Scan

```yaml
on:
  schedule:
    - cron: "0 2 * * *"    # Daily at 02:00 UTC

jobs:
  deep-scan:
    runs-on: ubuntu-latest
    steps:
      # ... setup ...
      - name: Deep fuzz scan
        run: |
          rtosploit scan \
            --firmware firmware.bin \
            --machine mps2-an385 \
            --fuzz-timeout 3600 \
            --fail-on medium \
            --output scan-output
```

---

## GitLab CI

```yaml
stages:
  - build
  - security

firmware-security-scan:
  stage: security
  image: python:3.12
  before_script:
    - apt-get update -qq && apt-get install -y qemu-system-arm
    - pip install -e .
  script:
    - >
      rtosploit scan
      --firmware firmware.bin
      --machine mps2-an385
      --fuzz-timeout 120
      --output scan-output
      --fail-on high
  artifacts:
    when: always
    paths:
      - scan-output/report.html
    reports:
      sast: scan-output/report.sarif.json
    expire_in: 30 days
  allow_failure: false

# Fast analysis-only job on feature branches
firmware-analysis:
  stage: security
  image: python:3.12
  before_script:
    - pip install -e .
  script:
    - rtosploit scan --firmware firmware.bin --machine mps2-an385 --skip-fuzz
  only:
    - branches
  except:
    - main
```

---

## Makefile Integration

```makefile
FIRMWARE     ?= firmware.bin
MACHINE      ?= mps2-an385
FUZZ_TIMEOUT ?= 120
FAIL_ON      ?= high
OUTPUT       ?= scan-output

.PHONY: security-scan analysis-only cve-check

security-scan:
	rtosploit scan \
		--firmware $(FIRMWARE) \
		--machine $(MACHINE) \
		--fuzz-timeout $(FUZZ_TIMEOUT) \
		--output $(OUTPUT) \
		--fail-on $(FAIL_ON)

analysis-only:
	rtosploit scan \
		--firmware $(FIRMWARE) \
		--machine $(MACHINE) \
		--skip-fuzz \
		--output $(OUTPUT)

cve-check:
	rtosploit cve scan --firmware $(FIRMWARE)

clean-scan:
	rm -rf $(OUTPUT)
```

Usage:

```bash
make security-scan FIRMWARE=./build/fw.bin FUZZ_TIMEOUT=300
make analysis-only FIRMWARE=./build/fw.bin
```

---

## Docker

```dockerfile
FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    qemu-system-arm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /rtosploit
COPY . .
RUN pip install -e .

ENTRYPOINT ["rtosploit"]
```

```bash
docker build -t rtosploit .
docker run --rm -v $(pwd):/work rtosploit scan \
  --firmware /work/firmware.bin \
  --machine mps2-an385 \
  --output /work/scan-output
```

---

## JSON Output in Pipelines

For custom integrations, use `--json` and parse stdout:

```bash
# Check if any critical CVEs exist
CRITICAL=$(rtosploit --json cve scan --firmware fw.bin \
  | jq '[.[] | select(.severity == "CRITICAL")] | length')
if [ "$CRITICAL" -gt 0 ]; then
  echo "Critical CVEs found: $CRITICAL"
  exit 1
fi

# Extract coverage percentage
COV=$(rtosploit --json coverage stats --firmware fw.bin --bitmap ./bitmap \
  | jq '.coverage_percent')
echo "Coverage: ${COV}%"
```

---

## Caching Strategies

### Cache the CVE Database

The CVE database is pre-populated. Avoid re-fetching on every run in CI by caching `~/.config/rtosploit/`:

```yaml
# GitHub Actions example
- name: Cache RTOSploit CVE database
  uses: actions/cache@v4
  with:
    path: ~/.config/rtosploit
    key: rtosploit-cve-${{ hashFiles('**/bundled_cves.json') }}
```

### Skip CVE Update in Offline Environments

```bash
rtosploit scan --firmware fw.bin --machine mps2-an385 --skip-cve
```

---

## Interpreting Results

### SARIF Integration

SARIF output integrates directly with:
- **GitHub Code Scanning** — Findings appear in the Security tab as code scanning alerts
- **VS Code** — Install the "SARIF Viewer" extension to browse findings inline
- **Azure DevOps** — Upload via the Security Center SAST integration

### Exit Code in CI

```bash
rtosploit scan --firmware fw.bin --machine mps2-an385
STATUS=$?
case $STATUS in
  0) echo "PASS — no significant findings" ;;
  1) echo "FAIL — security findings above threshold" ;;
  2) echo "ERROR — RTOSploit encountered an internal error" ;;
esac
```
