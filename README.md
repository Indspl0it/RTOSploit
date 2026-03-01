# RTOSploit

**RTOS Exploitation & Bare-Metal Fuzzing Framework**

RTOSploit is a security testing framework for embedded RTOS firmware. It provides grey-box fuzzing, static analysis, exploit module execution, CVE correlation, and automated report generation — all running entirely in QEMU with no physical hardware required.

**Supported RTOSes:** FreeRTOS · ThreadX · Zephyr
**Supported architectures:** ARM Cortex-M (M3/M4/M7/M33) · RISC-V RV32I

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Modes](#usage-modes)
- [CLI Reference](#cli-reference)
  - [Global Flags](#global-flags)
  - [emulate](#emulate)
  - [fuzz](#fuzz)
  - [exploit](#exploit)
  - [analyze](#analyze)
  - [cve](#cve)
  - [triage](#triage)
  - [coverage](#coverage)
  - [report](#report)
  - [scan](#scan)
  - [console](#console)
  - [payload](#payload)
  - [svd](#svd)
  - [vulnrange](#vulnrange)
- [Exploit Modules](#exploit-modules)
- [Machine Configurations](#machine-configurations)
- [Configuration File](#configuration-file)
- [CI/CD Integration](#cicd-integration)
- [Development](#development)
- [Documentation](#documentation)
- [License](#license)

---

## Features

### Grey-box Fuzzing
- QEMU-based firmware fuzzer with AFL-compatible coverage bitmaps
- Crash deduplication and seed corpus management
- Live dashboard: executions/sec, crash count, coverage percentage
- Optional native Rust fuzzer binary for maximum throughput
- Simulation mode when native fuzzer is unavailable (useful for pipeline testing)
- Multi-job parallel execution

### Static Analysis — No QEMU Required
- **RTOS fingerprinting** — Detect FreeRTOS, ThreadX, or Zephyr from binary patterns, with version and confidence score
- **Heap allocator detection** — Identify heap_1 through heap_5 (FreeRTOS), ThreadX byte pools, Zephyr slabs; locate heap base address
- **MPU configuration analysis** — Map ARM Cortex-M MPU regions, flag executable or writable overlaps, detect disabled protections
- **String extraction** — Extract and classify embedded strings including RTOS-specific markers

### Exploit Modules
- 15+ built-in modules targeting FreeRTOS, ThreadX, and Zephyr
- Categories: heap corruption, MPU bypass, ISR hijacking, TCB overwrite, Bluetooth LE, race conditions
- Non-destructive `check` mode for safe vulnerability probing
- Metasploit-style console with tab completion, history, and option validation

### Vulnerability Intelligence
- **CVE correlation** — Match detected RTOS type and version against a bundled NVD-sourced CVE database
- **CVE search** — Free-text search across CVE IDs, descriptions, and product names
- **NVD sync** — Pull latest entries from NIST with optional API key for higher rate limits

### Emulation & Debugging
- QEMU process orchestration with automatic version checking (requires 9.0+)
- GDB stub integration for live firmware debugging
- CMSIS-SVD peripheral modeling for accurate register-level emulation
- Serial/UART forwarding to TCP port

### Post-Fuzzing Analysis
- **Crash triage** — Classify exploitability (EXPLOITABLE, PROBABLY_EXPLOITABLE, UNKNOWN) using CFSR flags, fault types, and PC/SP control detection
- **Input minimization** — Automatically reduce crash inputs to minimal reproducing cases
- **Coverage visualization** — Annotated disassembly (terminal or HTML) with instruction-level hit counts

### Reporting
- **SARIF** — IDE-compatible format for VS Code, GitHub Code Scanning, Azure DevOps
- **HTML dashboard** — Interactive report with severity color-coding and finding details
- Severity-based CI pass/fail threshold (`--fail-on critical|high|medium|low|any`)

### Interactive Mode
- Arrow-key menus with contextual categories
- Path auto-completion for firmware files
- Firmware info panel: RTOS name, version, architecture, machine, confidence
- Live fuzzer dashboard embedded in the menu flow
- Post-fuzz triage and report generation without leaving the tool

---

## Installation

### Requirements

- Python 3.10 or later
- QEMU 9.0 or later with `qemu-system-arm` (and/or `qemu-system-riscv32`) in `PATH`
- Optional: Rust toolchain for the native fuzzer binary

### From Source

See [docs/installation.md](docs/installation.md) for full requirements, QEMU setup on all platforms, and optional Rust fuzzer build instructions.

```bash
git clone https://github.com/rtosploit/rtosploit
cd rtosploit
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

### Install QEMU

**Debian/Ubuntu:**
```bash
sudo apt install qemu-system-arm qemu-system-misc
```

**macOS (Homebrew):**
```bash
brew install qemu
```

**Verify the installation:**
```bash
qemu-system-arm --version   # must report 9.0.0 or later
```

### Native Fuzzer (optional)

The native Rust fuzzer provides real coverage-guided mutation. Without it, RTOSploit runs in **simulation mode**, which is still useful for pipeline and dashboard testing:

```bash
cargo build --release -p rtosploit-fuzzer
# The rtosploit-fuzzer binary is then automatically detected at runtime
```

---

## Quick Start

### Interactive Mode

Launch with no arguments:

```bash
rtosploit
```

Select **Load Firmware**, provide a path, and RTOSploit will auto-detect the format (ELF, Intel HEX, SREC, or raw binary), fingerprint the RTOS, select a default QEMU machine, and drop into the firmware menu.

### One-shot Security Scan

```bash
rtosploit scan \
  --firmware firmware.bin \
  --machine mps2-an385 \
  --fuzz-timeout 120 \
  --format both \
  --output ./results
```

Exit codes: `0` = pass, `1` = findings above threshold, `2` = error.

### Fuzz Only

```bash
rtosploit fuzz \
  --firmware firmware.bin \
  --machine mps2-an385 \
  --output ./fuzz-out \
  --timeout 300
```

### Static Analysis Only

```bash
rtosploit analyze --firmware firmware.bin --all
```

### CVE Check

```bash
rtosploit cve scan --firmware firmware.bin
```

---

## Usage Modes

### Interactive Mode

Run `rtosploit` with no arguments to enter the guided menu system:

```
  RTOSploit   Firmware Security Testing Framework

? What would you like to do?
❯ Load Firmware
  ──────────────
  Quick Scan (CI Pipeline)
  Search CVE Database
  ──────────────
  Interactive Console (Metasploit-style)
  ──────────────
  Settings
  Exit
```

After loading firmware, the menu expands with all relevant actions grouped by category:

```
? Select action:
  ── Emulation ──
❯ Boot Firmware in QEMU
  Attach GDB Debugger
  ── Security Testing ──
  Fuzz Firmware
  Run Exploit Modules
  Full Security Scan
  ── Analysis ──
  Static Analysis (fingerprint, heap, MPU, strings)
  CVE Correlation
  Triage Crash Directory
  ── Output ──
  View Coverage
  Generate Reports
  ──────────────
  Load Different Firmware
  Back to Main Menu
```

Use `--debug` for verbose logging in interactive mode:

```bash
rtosploit --debug
```

### CLI Mode

Any subcommand bypasses interactive mode:

```bash
rtosploit scan --help
rtosploit --json cve search "heap overflow"
rtosploit --quiet fuzz --firmware fw.bin --machine mps2-an385
```

---

## CLI Reference

### Global Flags

Available before any subcommand. Affect all commands.

| Flag | Short | Description |
|------|-------|-------------|
| `--verbose` | `-v` | Enable DEBUG-level logging |
| `--quiet` | `-q` | Suppress INFO messages; show only warnings and errors |
| `--json` | | Output results as machine-readable JSON |
| `--config PATH` | | Load settings from a custom `.rtosploit.yaml` |
| `--version` | | Print version and exit |
| `--help` | | Show help and exit |

```bash
# JSON output for scripting
rtosploit --json analyze --firmware fw.bin --all | jq '.rtos'

# Suppress noise in CI
rtosploit --quiet scan --firmware fw.bin --machine mps2-an385

# Custom config for a single run
rtosploit --config ./ci-config.yaml scan --firmware fw.bin --machine mps2-an385
```

---

### `emulate`

Launch a firmware image in QEMU.

```
rtosploit emulate --firmware PATH --machine NAME [OPTIONS]
```

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--firmware` | `-f` | **required** | Firmware binary (.bin, .elf, .hex) |
| `--machine` | `-m` | **required** | QEMU machine name (e.g. `mps2-an385`) |
| `--gdb` | | `false` | Enable GDB remote stub |
| `--gdb-port` | | `1234` | Port for the GDB stub |
| `--serial-port` | | none | Forward UART output to this TCP port |
| `--svd` | | none | CMSIS-SVD file for peripheral definitions |

```bash
# Basic boot
rtosploit emulate --firmware freertos_demo.elf --machine mps2-an385

# With GDB for live debugging
rtosploit emulate --firmware fw.bin --machine mps2-an385 --gdb --gdb-port 3333
# In another terminal:
arm-none-eabi-gdb -ex "target remote :3333" fw.elf

# With SVD peripheral accuracy
rtosploit emulate --firmware fw.bin --machine stm32f4 --svd STM32F407.svd

# JSON status for scripts
rtosploit --json emulate --firmware fw.bin --machine mps2-an385
```

---

### `fuzz`

Start QEMU-based grey-box fuzzing.

```
rtosploit fuzz --firmware PATH --machine NAME [OPTIONS]
```

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--firmware` | `-f` | **required** | Firmware binary |
| `--machine` | `-m` | **required** | QEMU machine name |
| `--rtos` | | `auto` | Override RTOS: `freertos`, `threadx`, `zephyr`, `auto` |
| `--output` | `-o` | `fuzz-output` | Output directory for crashes and corpus |
| `--seeds` | `-s` | none | Seed corpus directory |
| `--timeout` | `-t` | `0` | Stop after N seconds (0 = run indefinitely) |
| `--jobs` | `-j` | `1` | Parallel fuzzer instances |

Output structure created automatically:
```
fuzz-output/
  crashes/     # One JSON file per unique crash
  corpus/      # Corpus entries that increased coverage
```

Live dashboard during fuzzing:
```
┌─────────────────── RTOSploit Fuzzer Dashboard ──────────────────┐
│ Metric          Value                                            │
│ ─────────────── ─────────────────────────────────────────────── │
│ Elapsed Time    00:05:23                                         │
│ Executions      48,392                                           │
│ Exec/sec        149.9                                            │
│ Crashes Found   3                                                │
│ Coverage %      12.4%                                            │
│ Corpus Size     31                                               │
└─────────────────────────────────────────────────────────────────┘
```

```bash
# 5-minute session
rtosploit fuzz --firmware fw.bin --machine mps2-an385 --timeout 300

# With seeds, custom output, 4 parallel instances
rtosploit fuzz --firmware fw.bin --machine mps2-an385 \
  --seeds ./seeds --output ./fuzz-out --jobs 4 --timeout 3600

# JSON status only (no live dashboard)
rtosploit --json fuzz --firmware fw.bin --machine mps2-an385 --output ./out
```

---

### `exploit`

Manage and execute exploit modules.

#### `exploit list`

```bash
rtosploit exploit list
rtosploit --json exploit list
```

Table columns: Module Path, Name, RTOS, Category, Reliability, CVE.

#### `exploit info MODULE_PATH`

```bash
rtosploit exploit info freertos/heap_overflow
```

Shows description, all options with types and defaults, CVE if applicable.

#### `exploit run MODULE_PATH`

```bash
rtosploit exploit run freertos/heap_overflow \
  --firmware fw.bin \
  --machine mps2-an385 \
  --option PAYLOAD_ADDRESS=0x20001000 \
  --option HEAP_OFFSET=64
```

| Option | Short | Description |
|--------|-------|-------------|
| `--firmware` | `-f` | Target firmware binary |
| `--machine` | `-m` | QEMU machine name |
| `--option` | `-o` | Module option as `KEY=VALUE` (repeatable) |
| `--payload` | | Payload name or file path |

#### `exploit check MODULE_PATH`

Non-destructive vulnerability probe. Does not execute the exploit payload.

```bash
rtosploit exploit check freertos/mpu_bypass \
  --firmware fw.bin \
  --machine mps2-an385
```

---

### `analyze`

Static firmware analysis. Runs entirely without QEMU.

```
rtosploit analyze --firmware PATH [FLAGS]
```

| Option | Short | Description |
|--------|-------|-------------|
| `--firmware` | `-f` | **required** — Firmware binary |
| `--detect-rtos` | | Fingerprint RTOS type, version, and confidence |
| `--detect-heap` | | Identify heap allocator variant and base address |
| `--detect-mpu` | | Analyze ARM MPU regions and flag vulnerabilities |
| `--strings` | | Extract and classify embedded strings |
| `--all` | | Run all analyses |

```bash
# Quick RTOS check
rtosploit analyze --firmware fw.bin --detect-rtos

# Full analysis, JSON output
rtosploit --json analyze --firmware fw.bin --all
```

JSON output structure:
```json
{
  "firmware": "fw.bin",
  "rtos": {
    "detected": "freertos",
    "version": "10.4.3",
    "confidence": 0.92
  },
  "heap": {
    "type": "heap_4",
    "base": "0x20001800"
  },
  "mpu": {
    "present": true,
    "regions_configured": 4,
    "vulnerable": false,
    "vulnerabilities": []
  },
  "strings": {
    "count": 142,
    "sample": ["FreeRTOS", "IDLE", "prvIdleTask"]
  }
}
```

---

### `cve`

CVE database operations.

#### `cve scan`

Fingerprint firmware and list applicable CVEs.

```bash
rtosploit cve scan --firmware fw.bin
rtosploit cve scan --firmware fw.bin --rtos freertos --version "10.4.3"
```

| Option | Description |
|--------|-------------|
| `--firmware` | **required** — Firmware binary |
| `--rtos` | Override RTOS detection |
| `--version` | Override version detection |

Output table: CVE ID, CVSS, severity, exploit availability, description.

#### `cve search TERM`

```bash
rtosploit cve search "heap overflow"
rtosploit cve search CVE-2021-31571
rtosploit --json cve search freertos
```

#### `cve update`

Pull new entries from NIST NVD.

```bash
# Rate-limited (no key)
rtosploit cve update

# With API key
NVD_API_KEY=your-key rtosploit cve update

# Specific product only
rtosploit cve update --product freertos
```

---

### `triage`

Classify crash exploitability and minimize inputs.

```
rtosploit triage --crash-dir DIR --firmware PATH [OPTIONS]
```

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--crash-dir` | `-c` | **required** | Directory of crash JSON files |
| `--firmware` | `-f` | **required** | Firmware binary for replay |
| `--machine` | `-m` | `mps2-an385` | QEMU machine for replay |
| `--minimize` | | `true` | Reduce crash inputs to minimal size |
| `--format` | | `text` | Output format: `text`, `json`, `sarif` |
| `--output` | `-o` | stdout | Write to file instead of stdout |

**Exploitability classes:**

| Class | Meaning |
|-------|---------|
| `EXPLOITABLE` | PC control confirmed, executable redirect possible |
| `PROBABLY_EXPLOITABLE` | Partial control or write-what-where condition |
| `PROBABLY_NOT_EXPLOITABLE` | Crash without meaningful memory influence |
| `UNKNOWN` | Insufficient data to classify |

```bash
# Text output (human-readable)
rtosploit triage --crash-dir ./fuzz-out/crashes --firmware fw.bin

# SARIF for CI
rtosploit triage --crash-dir ./crashes --firmware fw.bin \
  --format sarif --output triage.sarif.json

# JSON for scripting
rtosploit --json triage --crash-dir ./crashes --firmware fw.bin
```

---

### `coverage`

Visualize fuzzing coverage against firmware disassembly.

#### `coverage view`

```bash
# Terminal view (default)
rtosploit coverage view --firmware fw.bin --bitmap ./fuzz-out/coverage.bitmap

# HTML report
rtosploit coverage view --firmware fw.bin --trace ./trace.log \
  --format html --output coverage.html
```

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--firmware` | `-f` | **required** | Firmware binary |
| `--bitmap` | `-b` | none | AFL-style coverage bitmap file |
| `--trace` | `-t` | none | Trace log file |
| `--base-address` | | `0x08000000` | Firmware load address (hex) |
| `--format` | | `terminal` | `terminal` or `html` |
| `--output` | `-o` | `coverage_report.html` | HTML output path |
| `--max-lines` | | `50` | Maximum lines in terminal view |

#### `coverage stats`

```bash
rtosploit --json coverage stats --firmware fw.bin --bitmap ./bitmap
```

```json
{
  "total_instructions": 4821,
  "covered_instructions": 1134,
  "coverage_percent": 23.5,
  "total_edges": 892,
  "hot_spots": [
    { "address": "0x00001248", "hits": 4821 },
    { "address": "0x0000124e", "hits": 3902 }
  ]
}
```

---

### `report`

Generate SARIF or HTML reports from collected findings.

```
rtosploit report --input-dir DIR --output DIR [OPTIONS]
```

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--input-dir` | `-i` | **required** | Directory with crash/exploit JSON files |
| `--output` | `-o` | **required** | Output directory |
| `--format` | `-f` | `both` | `sarif`, `html`, or `both` |
| `--firmware` | | `unknown` | Firmware name for report metadata |
| `--architecture` | | `armv7m` | Architecture for report metadata |

```bash
# Full report from scan output
rtosploit report \
  --input-dir ./scan-output \
  --output ./reports \
  --format both

# SARIF only for GitHub Code Scanning
rtosploit report \
  --input-dir ./crashes \
  --output ./sarif-out \
  --format sarif
```

SARIF reports are compatible with GitHub Code Scanning (`upload-sarif` action), VS Code SARIF Viewer, and Azure DevOps Security Center.

---

### `scan`

Full end-to-end security scan. Orchestrates all phases and returns a CI exit code.

```
rtosploit scan --firmware PATH --machine NAME [OPTIONS]
```

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--firmware` | `-f` | **required** | Firmware binary |
| `--machine` | `-m` | `mps2-an385` | QEMU machine |
| `--fuzz-timeout` | | `60` | Fuzzing phase duration (seconds) |
| `--format` | | `both` | Report format: `sarif`, `html`, `both` |
| `--output` | `-o` | `scan-output` | Output directory |
| `--fail-on` | | `critical` | Severity threshold: `critical`, `high`, `medium`, `low`, `any` |
| `--skip-fuzz` | | false | Skip fuzzing phase |
| `--skip-cve` | | false | Skip CVE correlation |
| `--no-minimize` | | false | Skip crash minimization |
| `--architecture` | | `armv7m` | Target architecture |

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | Clean — no findings at or above `--fail-on` severity |
| `1` | Findings found at or above threshold |
| `2` | Internal error (QEMU failure, missing file, etc.) |

**Pipeline phases:**
1. Load and validate firmware
2. RTOS fingerprinting (type, version, heap, MPU, strings)
3. CVE correlation
4. Grey-box fuzzing
5. Crash triage and minimization
6. Report generation

```bash
# Standard CI scan
rtosploit scan \
  --firmware firmware.bin \
  --machine mps2-an385 \
  --fuzz-timeout 120 \
  --output ./scan-output

# Analysis only, no fuzzing, no CVE
rtosploit scan --firmware fw.bin --machine mps2-an385 --skip-fuzz --skip-cve

# Fail on any finding
rtosploit scan --firmware fw.bin --machine mps2-an385 --fail-on any
```

**Output structure:**
```
scan-output/
  report.sarif.json
  report.html
  crashes/
  corpus/
  triage/
```

---

### `console`

Metasploit-style interactive REPL for exploit module execution.

```bash
rtosploit console
```

| Command | Description |
|---------|-------------|
| `use <module>` | Load a module (e.g. `use freertos/heap_overflow`) |
| `show options` | List all options for the current module |
| `show info` | Show module description, CVE, reliability rating |
| `show modules` | List all registered exploit modules |
| `set <key> <value>` | Set a module option |
| `unset <key>` | Clear a module option |
| `check` | Non-destructive vulnerability probe |
| `exploit` / `run` | Execute the loaded module |
| `back` | Deselect module, return to root prompt |
| `search <term>` | Search by name, CVE, RTOS, or category |
| `banner` | Display the ASCII art banner |
| `version` | Show version string |
| `help` | Display the command reference |
| `exit` / `quit` | Exit the console |

**Features:** Tab completion for module paths, option names, and commands. Command history at `~/.config/rtosploit/history`. Type validation for options (int, bool, float, port, path). Rich colored output.

**Example session:**
```
rtosploit> search freertos heap
rtosploit> use freertos/heap_overflow
rtosploit(freertos/heap_overflow)> show options
rtosploit(freertos/heap_overflow)> set firmware ./fw.bin
rtosploit(freertos/heap_overflow)> set machine mps2-an385
rtosploit(freertos/heap_overflow)> check
rtosploit(freertos/heap_overflow)> exploit
rtosploit(freertos/heap_overflow)> back
rtosploit> exit
```

---

### `payload`

Generate shellcode and ROP chains.

#### `payload shellcode`

```
rtosploit payload shellcode --arch ARCH --type TYPE [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--arch` | **required** | `armv7m` or `riscv32` |
| `--type` | **required** | Shellcode type (see below) |
| `--format` | `hex` | `raw`, `hex`, `c`, `python` |
| `--encoder` | `raw` | `raw`, `xor`, `nullfree` |
| `--bad-chars` | none | Hex bytes to avoid (e.g. `000a0d`) |
| `--length` | `16` | NOP count for `nop_sled` |
| `--address` | none | Target address for `vtor_redirect` |

**Types:**

| Type | Description |
|------|-------------|
| `nop_sled` | Architecture-aware NOP sled (ARM: 2 bytes/NOP, RISC-V: 4 bytes/NOP) |
| `infinite_loop` | Tight infinite loop (`0xFEE7` on ARM Thumb2) |
| `mpu_disable` | Write 0 to ARM MPU_CTRL register (`0xE000ED94`) |
| `vtor_redirect` | Overwrite VTOR at `0xE000ED08` with `--address` value |
| `register_dump` | Trigger fault to dump register state |

```bash
# ARM infinite loop, hex output
rtosploit payload shellcode --arch armv7m --type infinite_loop
# fee7

# Python format
rtosploit payload shellcode --arch armv7m --type infinite_loop --format python
# b'\xfe\xe7'

# C array format
rtosploit payload shellcode --arch armv7m --type mpu_disable --format c

# RISC-V NOP sled, 8 entries
rtosploit payload shellcode --arch riscv32 --type nop_sled --length 8

# JSON output
rtosploit --json payload shellcode --arch armv7m --type infinite_loop
```

#### `payload rop`

Scan a binary for ROP gadgets and build chains.

```
rtosploit payload rop --binary PATH [OPTIONS]
```

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--binary` | `-b` | **required** | Binary to scan |
| `--arch` | | `armv7m` | Architecture |
| `--goal` | | `mpu_disable` | `mpu_disable`, `vtor_overwrite`, `write_what_where` |
| `--bad-chars` | | none | Hex bytes to exclude from chain |
| `--load-addr` | | `0x00000000` | Firmware base address |
| `--format` | | `hex` | Output format |

```bash
rtosploit payload rop --binary fw.elf --goal mpu_disable
rtosploit --json payload rop --binary fw.bin --goal write_what_where
```

---

### `svd`

Work with CMSIS-SVD peripheral definition files.

#### `svd parse SVD_FILE`

Parse and display peripheral definitions.

```bash
rtosploit svd parse STM32F407.svd
rtosploit --json svd parse STM32F407.svd
```

#### `svd generate SVD_FILE`

Generate C peripheral handler stubs.

```bash
rtosploit svd generate STM32F407.svd --output ./stubs --mode fuzzer
```

| Option | Default | Description |
|--------|---------|-------------|
| `--mode` | `reset-value` | `reset-value`, `read-write`, or `fuzzer` |
| `--output` | `svd_stubs` | Output directory |

Generates per-peripheral `.c` files and a `peripheral_map.h` mapping table.

#### `svd download`

Download SVD from the CMSIS-SVD GitHub repository.

```bash
rtosploit svd download --device STM32F407 --output ./svd
rtosploit svd download --device nRF52840 --output ./svd
```

---

### `vulnrange`

CVE reproduction lab for training and skill development.

#### `vulnrange list`

```bash
rtosploit vulnrange list
rtosploit --json vulnrange list
```

Table: ID, title, RTOS, difficulty, category, CVSS score.

#### `vulnrange start RANGE_ID`

```bash
rtosploit vulnrange start CVE-2021-31571
```

#### `vulnrange hint RANGE_ID`

Progressive hints to guide exploitation.

```bash
rtosploit vulnrange hint CVE-2021-31571           # General hint
rtosploit vulnrange hint CVE-2021-31571 --level 2  # Detailed
rtosploit vulnrange hint CVE-2021-31571 --level 3  # Near-spoiler
```

#### `vulnrange solve RANGE_ID`

Run the reference exploit solution.

```bash
rtosploit vulnrange solve CVE-2021-31571
```

#### `vulnrange writeup RANGE_ID`

Display the full markdown writeup.

```bash
rtosploit vulnrange writeup CVE-2021-31571
```

#### `vulnrange verify RANGE_ID`

Check that all challenge assets are present and valid.

```bash
rtosploit vulnrange verify CVE-2021-31571
```

---

## Exploit Modules

### FreeRTOS

| Module | Category | Description |
|--------|----------|-------------|
| `freertos/heap_overflow` | Heap Corruption | Overflow into adjacent heap block headers to corrupt task management structures |
| `freertos/tcb_overwrite` | Memory Corruption | Overwrite the Task Control Block to redirect execution or escalate privileges |
| `freertos/mpu_bypass` | MPU | Bypass MPU protections via misconfigured region permissions |
| `freertos/mpu_bypass_rop` | MPU / ROP | ROP chain-based MPU bypass for use when direct writes are blocked |
| `freertos/isr_hijack` | ISR | Hijack the Interrupt Service Routine table to redirect interrupt handling |
| `freertos/tcp_stack` | Network | Exploit FreeRTOS+TCP stack vulnerabilities |

### ThreadX

| Module | Category | Description |
|--------|----------|-------------|
| `threadx/byte_pool` | Heap Corruption | Exploit the ThreadX byte pool allocator for arbitrary write |
| `threadx/kom` | Kernel | Kernel Object Manipulation — corrupt internal control structures |
| `threadx/thread_entry` | Code Execution | Redirect thread entry points to attacker-controlled code |

### Zephyr

| Module | Category | CVE |
|--------|----------|-----|
| `zephyr/ble_overflow` | Bluetooth LE | — |
| `zephyr/ble_cve_2023_4264` | Bluetooth LE | CVE-2023-4264 |
| `zephyr/ble_cve_2024_6135` | Bluetooth LE | CVE-2024-6135 |
| `zephyr/ble_cve_2024_6442` | Bluetooth LE | CVE-2024-6442 |
| `zephyr/syscall_race` | Race Condition | — |
| `zephyr/userspace_off` | Boundary Bypass | — |

---

## Machine Configurations

Machine definitions live in `configs/machines/` as YAML files. Use the filename stem as the `--machine` argument.

| Machine | QEMU Target | CPU | Architecture |
|---------|-------------|-----|--------------|
| `mps2-an385` | MPS2 AN385 | Cortex-M3 | armv7m |
| `mps2-an505` | MPS2 AN505 | Cortex-M33 | armv8m |
| `stm32f4` | STM32F4 | Cortex-M4 | armv7m |

### Adding a Custom Machine

Drop a YAML file in `configs/machines/<name>.yaml`:

```yaml
machine:
  name: my-board
  qemu_machine: mps2-an385
  cpu: cortex-m4
  architecture: armv7m

memory:
  flash:
    base: 0x00000000
    size: 0x00100000
  sram:
    base: 0x20000000
    size: 0x00020000

peripherals:
  uart0:
    base: 0x40001000
    size: 0x1000
    irq: 5
```

---

## Configuration File

RTOSploit loads configuration in precedence order (later overrides earlier):

1. Built-in defaults
2. `~/.config/rtosploit/config.yaml` — user-wide
3. `.rtosploit.yaml` — project-level (current directory)
4. `--config PATH` — explicit override
5. CLI flags — highest priority

**Example `.rtosploit.yaml`:**

```yaml
qemu:
  binary: /usr/local/bin/qemu-system-arm
  timeout: 30

gdb:
  port: 1234

output:
  format: json
  color: true

logging:
  level: info

fuzzer:
  default_timeout: 120
  jobs: 2
```

**Environment variables** use the `RTOSPLOIT_` prefix:

```bash
RTOSPLOIT_QEMU_BINARY=/opt/qemu/bin/qemu-system-arm \
  rtosploit emulate --firmware fw.bin --machine mps2-an385
```

---

## CI/CD Integration

See [docs/ci-integration.md](docs/ci-integration.md) for GitHub Actions, GitLab CI, Docker, Makefile, and JSON scripting examples.

### GitHub Actions

```yaml
name: Firmware Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install QEMU
        run: sudo apt install -y qemu-system-arm

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

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: scan-output/report.sarif.json
        if: always()

      - name: Save artifacts
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: scan-output/
        if: always()
```

### GitLab CI

```yaml
firmware-security-scan:
  image: python:3.12
  before_script:
    - apt-get update && apt-get install -y qemu-system-arm
    - pip install -e .
  script:
    - rtosploit scan
        --firmware firmware.bin
        --machine mps2-an385
        --fuzz-timeout 60
        --output scan-output
        --fail-on critical
  artifacts:
    paths:
      - scan-output/
    reports:
      sast: scan-output/report.sarif.json
  allow_failure: false
```

### Makefile Integration

```makefile
.PHONY: security-scan

security-scan:
	rtosploit scan \
		--firmware $(FIRMWARE) \
		--machine mps2-an385 \
		--fuzz-timeout $(FUZZ_TIMEOUT) \
		--output scan-output \
		--fail-on high
```

---

## Development

### Running Tests

```bash
# All unit tests
.venv/bin/python -m pytest tests/unit/ -v

# Specific test file
.venv/bin/python -m pytest tests/unit/test_interactive.py -v

# With coverage report
.venv/bin/python -m pytest tests/unit/ --cov=rtosploit --cov-report=html
```

### Writing an Exploit Module

See the full guide: [docs/writing-exploits.md](docs/writing-exploits.md)

1. Create `rtosploit/exploits/<rtos>/my_exploit.py`
2. Subclass `ExploitModule` from `rtosploit.exploits.base`
3. Set class attributes: `name`, `description`, `rtos`, `category`, `reliability`
4. Implement abstract methods: `check()`, `exploit()`, `requirements()`, `cleanup()`
5. Register options in `register_options()` with `self.add_option()`

The registry auto-discovers all modules in `rtosploit/exploits/`.

### Adding a New CLI Command

1. Create `rtosploit/cli/commands/my_command.py` with a Click command named `my_command`
2. Import and register in `rtosploit/cli/main.py`:
   ```python
   from rtosploit.cli.commands.my_command import my_command
   cli.add_command(my_command)
   ```

### Project Layout

```
rtosploit/
├── cli/
│   ├── main.py              Entry point, global flags, routing
│   └── commands/            One file per subcommand
├── interactive/
│   ├── app.py               Menu loop and dispatch
│   ├── banner.py            Rich ASCII banner
│   ├── menus.py             questionary menu definitions
│   ├── session.py           FirmwareContext + InteractiveSession
│   ├── firmware_loader.py   Load, fingerprint, display, machine selection
│   ├── dashboard.py         Shared live fuzzer dashboard
│   └── handlers/            One handler per firmware-menu action
├── exploits/
│   ├── base.py              ExploitModule ABC, ExploitOption, ExploitResult
│   ├── registry.py          Dynamic module discovery
│   ├── runner.py            Execution orchestration
│   ├── freertos/            6 FreeRTOS modules
│   ├── threadx/             3 ThreadX modules
│   └── zephyr/              6 Zephyr modules
├── analysis/
│   ├── fingerprint.py       RTOS type + version detection
│   ├── heap_detect.py       Heap allocator identification
│   ├── mpu_check.py         ARM MPU analysis
│   └── strings.py           String extraction
├── cve/
│   ├── database.py          JSON-backed CVE store
│   ├── correlator.py        RTOS fingerprint → CVE matching
│   └── nvd_client.py        NIST NVD API client
├── coverage/
│   ├── bitmap_reader.py     AFL bitmap parsing
│   ├── mapper.py            Address-level coverage mapping
│   └── visualizer.py        Terminal and HTML rendering
├── payloads/
│   ├── shellcode.py         Template generator (ARM + RISC-V)
│   └── rop.py               Gadget finder + chain builder
├── emulation/
│   ├── qemu.py              QEMU process lifecycle
│   ├── qmp.py               QEMU Machine Protocol client
│   ├── gdb.py               GDB stub integration
│   └── machines.py          Machine YAML loading
├── triage/
│   ├── pipeline.py          Load → classify → minimize → sort
│   └── classifier.py        Exploitability scoring
├── ci/
│   └── pipeline.py          Full scan orchestration
├── reporting/
│   ├── models.py            Finding + EngagementReport dataclasses
│   ├── sarif.py             SARIF generator
│   └── html.py              HTML dashboard generator
└── console/
    ├── repl.py              Metasploit-style REPL
    └── state.py             ConsoleState
```

---

## Documentation

Detailed documentation lives in the [`docs/`](docs/) directory:

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | System design, module dependency map, and Mermaid data-flow diagrams |
| [Installation](docs/installation.md) | Full requirements, QEMU setup, Rust fuzzer build, NVD API key |
| [Quick Start](docs/quickstart.md) | Step-by-step interactive walkthrough and CLI equivalents |
| [CI Integration](docs/ci-integration.md) | GitHub Actions, GitLab CI, Makefile, Docker, JSON scripting |
| [Writing Exploit Modules](docs/writing-exploits.md) | `ExploitModule` subclass template, option types, testing |
| [Writing VulnRange Labs](docs/writing-vulnranges.md) | Lab directory layout, `manifest.yaml` schema, hint conventions |
| [Crash Triage](docs/crash-triage.md) | CFSR register flags, exploitability classification, minimization |
| [CVE Correlation](docs/cve-correlation.md) | Database schema, matching logic, NVD sync, offline operation |
| [Coverage](docs/coverage.md) | AFL bitmap format, terminal/HTML views, improving coverage |
| [Reporting](docs/reporting.md) | SARIF structure, HTML dashboard, IDE integration, data model |

---

## License

GPL-3.0-only. See `LICENSE` for details.
