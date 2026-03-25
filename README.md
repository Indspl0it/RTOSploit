<p align="center">
  <img src="assets/banner.svg" alt="RTOSploit — RTOS Exploitation & Bare-Metal Fuzzing Framework" width="100%"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.6.0-blue" alt="Version 2.5.1"/>
  <a href="#installation"><img src="https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white" alt="Python 3.10+"/></a>
  <img src="https://img.shields.io/badge/tests-1528%20passing-brightgreen" alt="Tests"/>
  <img src="https://img.shields.io/badge/license-Apache--2.0-orange" alt="License"/>
  <img src="https://img.shields.io/badge/exploits-15%20modules-red" alt="Exploits"/>
</p>

<p align="center">
  <strong>Author:</strong> Santhosh Ballikonda
</p>

---

RTOSploit is a firmware security testing framework for embedded RTOS systems. It provides static analysis, CVE correlation, vulnerability assessment, payload generation, firmware emulation, and coverage-guided fuzzing — entirely in software, no physical hardware required.

**Supported RTOSes:** FreeRTOS, ThreadX, Zephyr, ESP-IDF, RTEMS (detection only)

**Supported Architectures:** ARM Cortex-M (M0/M3/M4/M7/M33), RISC-V (RV32I/RV64), Xtensa, MIPS, AArch64

**Binary Formats:** ELF, Intel HEX, Motorola S-Record, Raw binary

### What works on what

| Capability | Any firmware (ELF or raw .bin) | QEMU-targeted firmware | Via Unicorn + PIP |
|---|---|---|---|
| RTOS fingerprint | Yes (strings + symbols) | Yes | N/A |
| CVE correlation | Yes (59 bundled CVEs) | Yes | N/A |
| Peripheral detection | Yes (6-layer engine) | Yes | N/A |
| Exploit assessment | Yes (15 modules, static) | Yes | N/A |
| Payload/ROP generation | Yes | Yes | N/A |
| Emulate and boot | No (needs matching machine) | Yes | Yes (model-free) |
| Coverage-guided fuzzing | No | Yes (~3-5 exec/sec) | Yes (~200+ exec/sec) |

> **On real hardware firmware:** Static analysis, CVE correlation, exploit assessment, and payload generation work on any firmware binary. Emulation and fuzzing require either a matching QEMU machine or the Unicorn engine with Peripheral Input Playback (PIP), which drives all peripheral I/O from fuzz input without hardware models.

---

## Table of Contents

1. [Purpose](#purpose)
2. [Architecture](#architecture)
3. [Features](#features)
4. [Installation](#installation)
5. [Quick Start](#quick-start)
6. [Emulation Engines](#emulation-engines)
7. [CLI Reference](#cli-reference)
8. [Exploit Modules](#exploit-modules)
9. [Machine Configurations](#machine-configurations)
10. [Configuration](#configuration)
11. [CI/CD Integration](#cicd-integration)
12. [Development](#development)
13. [Troubleshooting](#troubleshooting)
14. [Acknowledgements](#acknowledgements)
15. [License](#license)

---

## Purpose

Embedded RTOS firmware (FreeRTOS, ThreadX, Zephyr) runs on billions of devices — medical implants, automotive ECUs, industrial PLCs, IoT gateways — yet security testing tools for these targets are fragmented, hardware-dependent, and expensive. RTOSploit provides a software-only alternative.

**Typical workflow:**

1. **Analyze** — fingerprint RTOS, version, MCU, heap allocator, MPU config, peripherals
2. **Correlate CVEs** — match against 59 bundled vulnerabilities from NVD
3. **Assess vulnerabilities** — run 15 exploit modules (heap corruption, MPU bypass, BLE overflows)
4. **Generate payloads** — ARM Thumb2/RISC-V shellcode, ROP chains, protocol packets
5. **Emulate** — boot firmware in QEMU (interactive) or Unicorn (high-speed)
6. **Fuzz** — coverage-guided fuzzing with crash deduplication and interrupt injection
7. **Report** — SARIF for CI/CD, HTML for review

Steps 1-4 work on any firmware binary. Steps 5-7 require either a QEMU-supported machine or the Unicorn engine.

**What RTOSploit does NOT do:**

- Run exploits on physical hardware — this is a software-only analysis and assessment tool
- Full symbolic execution — we use lightweight register tracking, not angr-style analysis
- Linux firmware analysis — RTOS and bare-metal only
- Hardware-in-the-loop testing — no JTAG/SWD integration

---

## Architecture

RTOSploit has two execution paths depending on the use case:

```
                         ┌──────────────────────────┐
                         │     Firmware Binary       │
                         │  (ELF / HEX / SREC / raw) │
                         └────────────┬─────────────┘
                                      │
                    ┌─────────────────┼─────────────────┐
                    ▼                 ▼                  ▼
            ┌──────────────┐  ┌─────────────┐  ┌──────────────┐
            │   Static     │  │    CVE      │  │   Exploit    │
            │  Analysis    │  │ Correlation │  │  Assessment  │
            │              │  │             │  │              │
            │ Fingerprint  │  │ 59 bundled  │  │ 15 modules   │
            │ Heap detect  │  │ CVEs from   │  │ FreeRTOS (6) │
            │ MPU check    │  │ NVD for     │  │ ThreadX  (3) │
            │ Peripheral   │  │ FreeRTOS    │  │ Zephyr   (6) │
            │ detection    │  │ ThreadX     │  │              │
            │ (6 layers)   │  │ Zephyr      │  │ + Payload    │
            │              │  │ ESP-IDF     │  │   generation │
            └──────────────┘  └─────────────┘  └──────────────┘
                    │                 │                  │
                    └─────────────────┼──────────────────┘
                                      │
                    Works on ANY firmware ▲
                   ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
                   Requires emulation ▼
                                      │
                    ┌─────────────────┼─────────────────┐
                    ▼                                    ▼
         ┌───────────────────┐              ┌───────────────────┐
         │   QEMU Engine     │              │  Unicorn Engine   │
         │                   │              │                   │
         │ Full system       │              │ CPU-only          │
         │ NVIC, SysTick     │              │ PIP-driven MMIO   │
         │ Machine-specific  │              │ FERMCov coverage  │
         │ GDB debugging     │              │ Interrupt sched.  │
         │ UART forwarding   │              │ Snapshot/restore  │
         │                   │              │                   │
         │ ~3-5 exec/sec     │              │ ~200+ exec/sec    │
         │                   │              │                   │
         │ For: interactive  │              │ For: automated    │
         │ debug, QEMU-      │              │ fuzzing, real     │
         │ targeted firmware │              │ hardware firmware │
         └─────────┬─────────┘              └─────────┬─────────┘
                   │                                   │
                   └───────────────┬───────────────────┘
                                   ▼
                    ┌──────────────────────────┐
                    │   Coverage-Guided        │
                    │   Fuzzing Engine         │
                    │                          │
                    │ AFL-style edge bitmap    │
                    │ Crash dedup (PC+CFSR)    │
                    │ Multi-worker parallel    │
                    │ Corpus management        │
                    └────────────┬─────────────┘
                                 ▼
                    ┌──────────────────────────┐
                    │   Post-Processing        │
                    │                          │
                    │ Crash triage             │
                    │ Input minimization       │
                    │ Coverage visualization   │
                    └────────────┬─────────────┘
                                 ▼
                    ┌──────────────────────────┐
                    │   Reporting              │
                    │                          │
                    │ SARIF 2.1.0 (CI/IDE)     │
                    │ HTML (human review)      │
                    │ JSON (API/scripting)     │
                    └──────────────────────────┘
```

---

## Features

### Static Analysis

Works on any firmware binary — no QEMU, no symbols required.

| Analysis | What it finds |
|----------|--------------|
| RTOS Fingerprint | FreeRTOS, ThreadX, Zephyr, ESP-IDF, RTEMS — type, version, confidence |
| MCU Detection | nRF52, STM32F4, ESP32, LPC, SAM, RP2040 |
| Heap Allocator | FreeRTOS heap_1–heap_5, ThreadX byte pools, Zephyr slabs |
| MPU Configuration | ARM Cortex-M MPU regions, executable/writable overlaps |
| Peripheral Detection | 6-layer engine: symbol, string, relocation, MMIO register, binary signature, devicetree |
| String Extraction | RTOS markers, SDK references, error messages |

### CVE Intelligence

- 59 bundled CVEs across FreeRTOS, ThreadX, Zephyr, and ESP-IDF
- Version-aware matching with underlying RTOS lookup (ESP-IDF includes FreeRTOS CVEs)
- NVD API sync for latest vulnerabilities
- VulnRange — CTF-style CVE reproduction challenges with progressive hints

### Vulnerability Assessment and Payload Generation

15 exploit modules that detect vulnerability patterns via static analysis and generate concrete artifacts.

| Category | Count | Produces |
|----------|-------|----------|
| Heap Corruption | 4 | Overflow buffers, fake metadata, write primitives |
| MPU Bypass | 2 | Privilege escalation payloads, ROP chains |
| ISR Hijacking | 1 | Vector table redirect payloads |
| BLE Exploits | 4 | Malformed advertising, L2CAP, ASCS packets |
| Kernel Attacks | 2 | TCB/thread entry overwrites, syscall chains |
| Reconnaissance | 2 | Userspace config detection, race conditions |

Standalone payload tools: ARM Thumb2 and RISC-V shellcode templates (NOP sled, infinite loop, MPU disable, VTOR redirect), ROP gadget finder with bad-character filtering, XOR and null-free encoders.

### Firmware Emulation

Two engines for different use cases — see [Emulation Engines](#emulation-engines) for details.

**QEMU** — full system emulation with GDB debugging, UART forwarding, and machine-specific peripherals. For interactive analysis and firmware built for QEMU-supported machines.

**Unicorn** — CPU-only emulation with Peripheral Input Playback (PIP). All MMIO reads return fuzz-controlled values with smart replay for status register polls. For automated fuzzing of real hardware firmware at high speed.

### Coverage-Guided Fuzzing

- AFL-style 64KB edge coverage bitmap
- Interrupt-aware coverage (FERMCov) — separates ISR edges from program edges, reducing false unique paths by 75-88%
- Round-robin interrupt scheduling with WFI/WFE detection
- Crash detection: unmapped memory access, permission violations, infinite loops, timeouts
- Crash deduplication: PC + CFSR + nearby-PC + backtrace frame matching
- Seed corpus management with coverage-guided mutation
- Multi-worker parallel execution
- Live dashboard: executions/sec, crash count, coverage percentage

### Post-Fuzzing Analysis

- **Crash Triage** — exploitability classification: EXPLOITABLE, PROBABLY_EXPLOITABLE, PROBABLY_NOT, UNKNOWN
- **Input Minimization** — automatically reduce crash inputs to minimal reproducing cases
- **Coverage Visualization** — instruction-level hit maps in terminal or HTML

### Reporting

| Format | Purpose | Integration |
|--------|---------|------------|
| SARIF 2.1.0 | Machine-readable | GitHub Code Scanning, VS Code, Azure DevOps |
| HTML | Human-readable | Executive review, sharing |
| JSON | API consumption | Scripting, tool chaining |

CI exit codes: `0` = clean, `1` = findings above threshold, `2` = error.

### Interactive Mode

Arrow-key TUI with contextual menus. Load firmware, and RTOSploit auto-detects format, RTOS, architecture, and MCU. Metasploit-style console with tab completion, command history, and option validation.

---

## Installation

**Requirements:**
- Python 3.10+
- QEMU 7.0+ with `qemu-system-arm` in PATH (for QEMU engine)
- Optional: `unicorn` Python package (for Unicorn engine)

**From source:**

```
git clone https://github.com/Indspl0it/RTOSploit
cd RTOSploit
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

**Install QEMU (Debian/Ubuntu):**

```
sudo apt install qemu-system-arm qemu-system-misc
```

**Install QEMU (macOS):**

```
brew install qemu
```

**Install Unicorn engine (optional, for high-speed fuzzing):**

```
pip install unicorn
```

See [docs/installation.md](docs/installation.md) for platform-specific instructions.

---

## Quick Start

**Analyze any firmware:**

```
rtosploit analyze -f firmware.elf --all
```

**Scan for known CVEs:**

```
rtosploit cve scan -f firmware.elf
```

**Fuzz firmware targeting a QEMU machine:**

```
rtosploit fuzz -f firmware.elf -m mps2-an385 --timeout 300
```

**Fuzz real hardware firmware (Unicorn + PIP):**

```
rtosploit fuzz -f real-product.elf --engine unicorn --timeout 300
```

**Full CI/CD scan:**

```
rtosploit scan -f firmware.elf --fuzz-timeout 120 --format sarif --output results --fail-on high
```

**Interactive mode:**

```
rtosploit
```

---

## Emulation Engines

### QEMU — Interactive Debugging

Use QEMU when firmware targets a supported machine and you want to interact with it.

**When to use:**
- Firmware built for mps2-an385, lm3s6965evb, microbit, stm32f4, or other QEMU machines
- You need UART output, GDB breakpoints, or step-through debugging
- Interactive analysis where you observe firmware behavior

**What QEMU provides:**
- Full ARM Cortex-M system: NVIC, SysTick, machine-specific peripherals
- GDB remote stub for live debugging
- HAL function intercepts (112 functions across STM32, nRF5, Zephyr)
- SVD-backed register models when available
- UART/serial forwarding to TCP port

**Commands:**

```
rtosploit emulate -f firmware.elf -m mps2-an385 --gdb
rtosploit rehost -f firmware.elf -m mps2-an385
rtosploit fuzz -f firmware.elf -m mps2-an385 --timeout 300
```

### Unicorn — High-Speed Fuzzing

Use Unicorn when firmware targets real hardware (nRF52840, STM32F407, etc.) or when you need speed.

**When to use:**
- Real product firmware that doesn't match a QEMU machine
- Automated fuzzing campaigns where throughput matters
- You want all peripheral I/O controlled by the fuzzer

**What Unicorn provides:**
- CPU-only emulation (ARM Thumb2) — no machine-specific peripherals
- Peripheral Input Playback (PIP) — MMIO reads return fuzz-controlled values with 2-bit replay optimization for status register polls
- FERMCov — interrupt-aware edge coverage that eliminates 75-88% of false unique paths
- Round-robin interrupt scheduling with WFI/WFE handling
- Fast snapshot/restore for fuzz iteration resets

**Commands:**

```
rtosploit rehost -f real-product.elf --engine unicorn
rtosploit fuzz -f real-product.elf --engine unicorn --timeout 300
```

### Engine Comparison

| | QEMU | Unicorn |
|---|---|---|
| Throughput | ~3-5 exec/sec | ~200+ exec/sec |
| Real hardware firmware | Needs matching machine | Works via PIP |
| Debugging | GDB, breakpoints, UART | No interactive debug |
| Peripheral modeling | Machine-native + HAL hooks | PIP (fuzz-driven) |
| Coverage | Basic block bitmap | AFL edge + FERMCov |
| Best for | Interactive analysis | Automated fuzzing |

---

## CLI Reference

### Global Flags

| Flag | Description |
|------|-------------|
| `--version` | Show version banner |
| `-v, --verbose` | DEBUG-level logging |
| `-q, --quiet` | Warnings and errors only |
| `--json` | Machine-readable JSON output |
| `--config PATH` | Custom config file |

### Commands

| Command | Description |
|---------|-------------|
| `analyze` | Static firmware analysis (RTOS, heap, MPU, peripherals) |
| `cve` | CVE correlation (`scan`, `search`, `update`) |
| `exploit` | Vulnerability assessment (`list`, `info`, `check`, `run`) |
| `payload` | Shellcode and ROP generation (`shellcode`, `rop`) |
| `emulate` | QEMU emulation with optional GDB |
| `rehost` | Peripheral-aware rehosting (QEMU or Unicorn) |
| `fuzz` | Coverage-guided fuzzing (QEMU or Unicorn) |
| `triage` | Crash classification and input minimization |
| `coverage` | Coverage visualization (`stats`, `view`) |
| `report` | SARIF and HTML report generation |
| `scan` | Full CI/CD pipeline (analyze → CVE → fuzz → triage → report) |
| `console` | Metasploit-style interactive REPL |
| `svd` | SVD file operations (`parse`, `download`, `generate`) |
| `vulnrange` | CVE reproduction labs (`list`, `start`, `hint`, `solve`) |

Run `rtosploit <command> --help` for detailed options.

---

## Exploit Modules

### FreeRTOS (6 modules)

| Module | Category | CVE | Description |
|--------|----------|-----|-------------|
| `freertos/heap_overflow` | Heap Corruption | — | BlockLink_t unlink, arbitrary write to TCB |
| `freertos/tcb_overwrite` | Memory Corruption | — | Direct pxTopOfStack overwrite |
| `freertos/isr_hijack` | ISR Hijacking | — | VTOR exception vector redirection |
| `freertos/mpu_bypass` | MPU Bypass | CVE-2021-43997 | xPortRaisePrivilege callable from unprivileged |
| `freertos/mpu_bypass_rop` | MPU + ROP | CVE-2024-28115 | Stack overflow ROP chain to disable MPU |
| `freertos/tcp_stack` | Network | CVE-2018-16525, CVE-2018-16528 | DNS/LLMNR response overflow |

### ThreadX (3 modules)

| Module | Category | Description |
|--------|----------|-------------|
| `threadx/byte_pool` | Heap Corruption | TX_BYTE_POOL unlink, arbitrary write |
| `threadx/kom` | Kernel | Kernel Object Masquerading (USENIX Security 2025) |
| `threadx/thread_entry` | Code Execution | Thread entry function pointer overwrite |

### Zephyr (6 modules)

| Module | Category | CVE | Description |
|--------|----------|-----|-------------|
| `zephyr/ble_overflow` | BLE | CVE-2024-6259 | Extended advertising heap overflow |
| `zephyr/ble_cve_2023_4264` | BLE | CVE-2023-4264 | BT Classic L2CAP overflow |
| `zephyr/ble_cve_2024_6135` | BLE | CVE-2024-6135 | Missing bounds in BT processing |
| `zephyr/ble_cve_2024_6442` | BLE | CVE-2024-6442 | ASCS global buffer overflow |
| `zephyr/syscall_race` | Race Condition | GHSA-3r6j-5mp3-75wr | SVC handler TOCTOU |
| `zephyr/userspace_off` | Reconnaissance | — | Detects CONFIG_USERSPACE=n |

---

## Machine Configurations

YAML files in `configs/machines/`. Use the filename as `--machine`:

| Machine | CPU | Architecture | Use Case |
|---------|-----|-------------|----------|
| `mps2-an385` | Cortex-M3 | armv7m | Generic ARM testing (default) |
| `mps2-an505` | Cortex-M33 | armv8m | TrustZone testing |
| `stm32f4` | Cortex-M4 | armv7m | STM32 HAL firmware |
| `microbit` | Cortex-M0 | armv6m | nRF51/nRF52 firmware |
| `lm3s6965evb` | Cortex-M3 | armv7m | TI Stellaris firmware |
| `sifive_e` | E31 | riscv32 | RISC-V testing |

---

## Configuration

RTOSploit loads config in precedence order:

1. Built-in defaults
2. `~/.config/rtosploit/config.yaml` — user-wide
3. `.rtosploit.yaml` — project-level
4. `--config PATH` — explicit override
5. CLI flags — highest priority

Environment variables use `RTOSPLOIT_` prefix.

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Firmware Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: sudo apt install -y qemu-system-arm
      - run: pip install -e .
      - run: |
          rtosploit scan \
            -f firmware.elf \
            --fuzz-timeout 120 \
            --format sarif \
            --output scan-output \
            --fail-on high
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: scan-output/report.sarif.json
        if: always()
```

See [docs/ci-integration.md](docs/ci-integration.md) for GitLab CI, Docker, and Makefile examples.

---

## Development

**Running tests:**

```
python -m pytest tests/unit/ -v
python -m pytest tests/unit/ --cov=rtosploit
```

**Project layout:**

```
rtosploit/
├── analysis/           Static analysis (fingerprint, heap, MPU, peripheral detection)
├── peripherals/        Peripheral modeling (HAL database, SVD, PIP handler, rehosting)
├── fuzzing/            Fuzzing engine (corpus, mutator, crash reporter, Unicorn worker)
├── coverage/           Coverage collection (AFL bitmap, FERMCov)
├── exploits/           Exploit modules (FreeRTOS, ThreadX, Zephyr)
├── emulation/          QEMU orchestration (process, GDB, QMP, machines)
├── cve/                CVE database and correlation
├── payloads/           Shellcode and ROP generation
├── triage/             Crash classification and minimization
├── reporting/          SARIF and HTML report generation
├── cli/                CLI commands (14 subcommands)
├── console/            Metasploit-style REPL
├── interactive/        Arrow-key TUI
└── vulnrange/          CVE reproduction labs
```

See [docs/writing-exploits.md](docs/writing-exploits.md) for the exploit module development guide.

---

## Troubleshooting

**QEMU not found** — Install QEMU 7.0+ and ensure `qemu-system-arm` is in PATH.

**SVD download fails** — CMSIS-SVD URLs change periodically. Use `--svd /path/to/file.svd` to provide manually.

**Fuzzer reports 0 exec/sec** — Firmware may not boot. Try `rtosploit emulate` first to verify. For real hardware firmware, use `--engine unicorn`.

**Exploit check says "not_vulnerable"** — Modules assess binary patterns. A CVE match by version doesn't guarantee the vulnerable code path is present — the vendor may have backported fixes.

**Unicorn not available** — Install with `pip install unicorn`. QEMU mode works without it.

**Large firmware causes timeouts** — Signature detection caps at 512KB per section. Provide SVD directly via `--svd`.

---

## Acknowledgements

RTOSploit builds on techniques from the embedded security research community.

### Research

| Paper | Authors | Venue | Technique |
|-------|---------|-------|-----------|
| **Ember-IO** | Farrelly, Chesser, Ranasinghe | ASIA CCS 2023 | Peripheral Input Playback (PIP), FERMCov |
| **HALucinator** | Clements et al. | NDSS 2020 | HAL function interception |
| **P2IM** | Feng et al. | USENIX Security 2020 | Register type inference |
| **Fuzzware** | Scharnowski et al. | USENIX Security 2022 | MMIO model generation |

### Open Source

| Project | License | Usage |
|---------|---------|-------|
| [QEMU](https://www.qemu.org/) | GPL-2.0 | System emulation |
| [Unicorn](https://www.unicorn-engine.org/) | GPL-2.0 | CPU emulation for fuzzing |
| [Capstone](https://www.capstone-engine.org/) | BSD-3-Clause | Disassembly |
| [pyelftools](https://github.com/eliben/pyelftools) | Public Domain | ELF parsing |
| [CMSIS-SVD](https://github.com/cmsis-svd/cmsis-svd-data) | Apache-2.0 | Peripheral definitions |

### Citation

If you use RTOSploit in academic work, please cite:

```
RTOSploit: RTOS Exploitation & Bare-Metal Fuzzing Framework
https://github.com/Indspl0it/RTOSploit
```

The PIP and FERMCov techniques are based on:

```
Guy Farrelly, Michael Chesser, and Damith C. Ranasinghe. 2023.
Ember-IO: Effective Firmware Fuzzing with Model-Free Memory Mapped IO.
ASIA CCS 2023. https://doi.org/10.1145/3579856.3582840
```

---

## License

Apache-2.0. See [LICENSE](LICENSE) for details.
